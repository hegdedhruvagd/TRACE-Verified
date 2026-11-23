"""Loopback standard-library HTTP server for TRACE-Verified SOC Workbench.

Implements Milestone 1 REST endpoints:
- GET  /api/v1/health
- GET  /api/v1/ollama
- GET  /api/v1/samples
- POST /api/v1/samples/{sample_id}/analyze
- POST /api/v1/analyze
- POST /api/v1/analyses/{analysis_id}/explanations
- GET  /api/v1/analyses/{analysis_id}/explanations
- GET  /api/v1/analyses/{analysis_id}
- GET  / and /static/* (safely confined to web/)
"""

from __future__ import annotations

import email
import email.parser
import email.policy
import hashlib
import ipaddress
import json
import mimetypes
import os
import queue
import re
import shutil
import signal
import sys
import tempfile
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .cli import _explain_selected
from .detection import Finding
from .incidents import CorrelatedIncident
from .pipeline import AnalysisConfig, analyze_paths
from .schemas import CanonicalEvent

# Server limits & security
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
DEFAULT_EXPLANATION_TIMEOUT_SECONDS = 180.0
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTENSIONS = {".csv", ".json", ".jsonl", ".ndjson"}

# Project paths
REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
ACCEPTANCE_DIR = REPO_ROOT / ".acceptance" / "TRACE-Verified-M4-20261123"
WEB_DIR = REPO_ROOT / "web"

# Pre-configured sample catalog
SAMPLE_CATALOG: dict[str, dict[str, Any]] = {
    "attack_chain": {
        "id": "attack_chain",
        "name": "Full Attack Chain",
        "description": "Multi-stage attack: Brute-force -> Successful login -> Privilege addition -> Suspicious execution",
        "files": ["attack_chain.jsonl"],
        "base_dir": ACCEPTANCE_DIR,
    },
    "attack_chain_mshta": {
        "id": "attack_chain_mshta",
        "name": "Attack Chain with mshta Script Host",
        "description": "Multi-stage attack involving mshta.exe execution and defense evasion",
        "files": ["attack_chain_mshta.jsonl"],
        "base_dir": ACCEPTANCE_DIR,
    },
    "benign": {
        "id": "benign",
        "name": "Benign Administrative Activity",
        "description": "Legitimate admin activities without malicious indicators",
        "files": ["benign.jsonl"],
        "base_dir": ACCEPTANCE_DIR,
    },
    "prompt_injection": {
        "id": "prompt_injection",
        "name": "Prompt Injection Defense Test",
        "description": "Command line attempting prompt injection to alter deterministic scoring",
        "files": ["prompt_injection.jsonl"],
        "base_dir": ACCEPTANCE_DIR,
    },
    "windows_audit": {
        "id": "windows_audit",
        "name": "Windows Audit Events",
        "description": "Windows logon events and group change events from tests/fixtures",
        "files": ["windows_timecreated.jsonl", "windows_privilege_events.jsonl"],
        "base_dir": FIXTURES_DIR,
    },
    "malformed_sample": {
        "id": "malformed_sample",
        "name": "Malformed and Partial Rows",
        "description": "Test file with malformed rows verifying graceful degradation",
        "files": ["malformed.jsonl"],
        "base_dir": FIXTURES_DIR,
    },
}


@dataclass
class StoredAnalysis:
    analysis_id: str
    created_at: datetime
    payload: dict[str, Any]
    events: list[CanonicalEvent]
    findings: list[Finding]
    incidents: list[CorrelatedIncident]
    job_status: str = "none"  # "none", "queued", "running", "completed", "failed"
    ai_explanations: list[dict[str, Any]] = field(default_factory=list)
    job_error: str | None = None


# Thread-safe in-memory registry of analyses
_ANALYSES_LOCK = threading.Lock()
_ANALYSES: dict[str, StoredAnalysis] = {}

# Background explanation worker queue
_EXPLANATION_QUEUE: queue.Queue[tuple[str, int, float]] = queue.Queue()
_WORKER_THREAD: threading.Thread | None = None
_WORKER_STARTED = False


def _explanation_worker() -> None:
    """Sequential worker for local Ollama explanation tasks to protect CPU inference."""
    while True:
        try:
            item = _EXPLANATION_QUEUE.get()
            if item is None:
                break
            analysis_id, max_explain, timeout_seconds = item
            with _ANALYSES_LOCK:
                stored = _ANALYSES.get(analysis_id)
                if not stored:
                    _EXPLANATION_QUEUE.task_done()
                    continue
                stored.job_status = "running"

            try:
                explanations = _explain_selected(
                    stored.payload,
                    stored.incidents,
                    stored.findings,
                    stored.events,
                    max_explain=max_explain,
                    timeout_seconds=timeout_seconds,
                )
                with _ANALYSES_LOCK:
                    stored.ai_explanations = explanations
                    stored.payload["ai_explanations"] = explanations
                    stored.job_status = "completed"
            except Exception as exc:
                with _ANALYSES_LOCK:
                    stored.job_status = "failed"
                    stored.job_error = str(exc)
            finally:
                _EXPLANATION_QUEUE.task_done()
        except Exception:
            # Prevent worker crash on unexpected queue errors
            pass


def ensure_worker_started() -> None:
    global _WORKER_THREAD, _WORKER_STARTED
    with _ANALYSES_LOCK:
        if not _WORKER_STARTED:
            _WORKER_THREAD = threading.Thread(
                target=_explanation_worker, daemon=True, name="OllamaWorker"
            )
            _WORKER_THREAD.start()
            _WORKER_STARTED = True


def sanitize_filename(raw_name: str | None, default_stem: str = "upload") -> str:
    """Sanitize filename to prevent directory traversal and invalid characters."""
    if not raw_name:
        return f"{default_stem}.jsonl"
    name = Path(raw_name).name
    ext = Path(name).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        ext = ".jsonl"
    stem = Path(name).stem
    cleaned_stem = re.sub(r"[^A-Za-z0-9_.-]", "_", stem).strip("._")
    if not cleaned_stem:
        cleaned_stem = default_stem
    return f"{cleaned_stem}{ext}"


def _supported_upload_name(raw_name: str | None) -> bool:
    """Reject declared unsupported file types before filename sanitization."""
    if not raw_name:
        return True
    if not isinstance(raw_name, str):
        return False
    return Path(raw_name).suffix.casefold() in ALLOWED_EXTENSIONS


def _parse_analysis_config(options_data: Any) -> AnalysisConfig:
    if not isinstance(options_data, dict):
        raise ValueError("Analysis options must be a JSON object.")
    try:
        return AnalysisConfig.from_dict(options_data)
    except (TypeError, ValueError, OverflowError) as exc:
        raise ValueError(f"Invalid analysis options: {exc}") from exc


class _LocalRedirectRefused(HTTPRedirectHandler):
    """Do not let a local Ollama probe follow a redirect to another host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def check_ollama_status(
    base_url: str = "http://localhost:11434", timeout: float = 1.0
) -> dict[str, Any]:
    """Loopback-only check of local Ollama health and model availability."""
    target_url = "http://127.0.0.1:11434/api/tags"
    req = Request(target_url, headers={"User-Agent": "TRACE-Verified/0.1.0"})
    try:
        opener = build_opener(ProxyHandler({}), _LocalRedirectRefused())
        with opener.open(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [
                m.get("name", "")
                for m in data.get("models", [])
                if isinstance(m, dict) and "name" in m
            ]
            has_phi4 = any(
                "phi4-mini" in m or m.startswith("phi4-mini:") for m in models
            )
            return {
                "available": True,
                "base_url": base_url,
                "configured_model": "phi4-mini:latest",
                "model_installed": has_phi4,
                "models": models,
                "message": "Local Ollama is running.",
            }
    except (URLError, TimeoutError, OSError) as exc:
        return {
            "available": False,
            "base_url": base_url,
            "configured_model": "phi4-mini:latest",
            "model_installed": False,
            "models": [],
            "message": f"Local Ollama is unreachable on loopback: {exc}",
        }


class SOCHandler(BaseHTTPRequestHandler):
    server_version = "TRACE-Verified/0.1.0"

    def is_loopback_client(self) -> bool:
        """Enforce that incoming connections originate strictly from loopback."""
        client_ip = self.client_address[0]
        try:
            return ipaddress.ip_address(client_ip).is_loopback
        except ValueError:
            return False

    def send_json(self, status_code: int, data: Any) -> None:
        """Send JSON response with strict security headers."""
        rendered = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(rendered)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store, max-age=0")
        self.end_headers()
        self.wfile.write(rendered)

    def send_error_json(self, status_code: int, message: str) -> None:
        self.send_json(status_code, {"error": message, "status": status_code})

    def do_OPTIONS(self) -> None:
        """Refuse permissive CORS; allow only basic same-origin preflights."""
        if not self.is_loopback_client():
            self.send_error_json(403, "Forbidden")
            return
        self.send_response(HTTPStatus.NO_CONTENT)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:
        if not self.is_loopback_client():
            self.send_error_json(403, "Access forbidden: loopback only.")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        if not path:
            path = "/"

        # 1. Health check
        if path == "/api/v1/health":
            with _ANALYSES_LOCK:
                active_count = len(_ANALYSES)
            self.send_json(
                200,
                {
                    "status": "ok",
                    "version": "0.1.0",
                    "engine": "deterministic",
                    "server_time": datetime.now(timezone.utc).isoformat(),
                    "active_analyses": active_count,
                },
            )
            return

        # 2. Local Ollama status check
        if path == "/api/v1/ollama":
            status = check_ollama_status()
            self.send_json(200, status)
            return

        # 3. Available samples catalog
        if path == "/api/v1/samples":
            sample_list = []
            for item in SAMPLE_CATALOG.values():
                base_dir = item["base_dir"]
                files_exist = all((base_dir / f).exists() for f in item["files"])
                sample_list.append(
                    {
                        "id": item["id"],
                        "name": item["name"],
                        "description": item["description"],
                        "files": item["files"],
                        "available": files_exist,
                    }
                )
            self.send_json(200, {"samples": sample_list})
            return

        # 4. Explanations polling: /api/v1/analyses/{analysis_id}/explanations
        if path.startswith("/api/v1/analyses/") and path.endswith("/explanations"):
            parts = path.split("/")
            if len(parts) == 6:
                analysis_id = parts[4]
                with _ANALYSES_LOCK:
                    stored = _ANALYSES.get(analysis_id)
                if not stored:
                    self.send_error_json(404, f"Analysis '{analysis_id}' not found.")
                    return
                self.send_json(
                    200,
                    {
                        "analysis_id": analysis_id,
                        "job_status": stored.job_status,
                        "ai_explanations": stored.ai_explanations,
                        "job_error": stored.job_error,
                    },
                )
                return

        # 5. Full analysis report: /api/v1/analyses/{analysis_id}
        if path.startswith("/api/v1/analyses/"):
            parts = path.split("/")
            if len(parts) == 5:
                analysis_id = parts[4]
                with _ANALYSES_LOCK:
                    stored = _ANALYSES.get(analysis_id)
                if not stored:
                    self.send_error_json(404, f"Analysis '{analysis_id}' not found.")
                    return
                resp = dict(stored.payload)
                resp["analysis_id"] = analysis_id
                resp["job_status"] = stored.job_status
                if stored.ai_explanations:
                    resp["ai_explanations"] = stored.ai_explanations
                self.send_json(200, resp)
                return

        # 6. Static files (safely resolved within WEB_DIR)
        self.serve_static_file(parsed.path)

    def do_POST(self) -> None:
        if not self.is_loopback_client():
            self.send_error_json(403, "Access forbidden: loopback only.")
            return

        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        # Check content-length against max upload limit
        content_length_header = self.headers.get("Content-Length")
        if not content_length_header:
            self.send_error_json(411, "Length Required: Content-Length header is missing.")
            return

        try:
            content_length = int(content_length_header)
        except ValueError:
            self.send_error_json(400, "Invalid Content-Length header.")
            return

        if content_length < 0:
            self.send_error_json(400, "Invalid Content-Length header: value must not be negative.")
            return

        if content_length > MAX_UPLOAD_BYTES:
            self.send_error_json(
                413,
                f"Payload Too Large: {content_length} bytes exceeds limit of {MAX_UPLOAD_BYTES} bytes.",
            )
            return

        body = self.rfile.read(content_length)

        # Route 1: POST /api/v1/samples/{sample_id}/analyze
        if path.startswith("/api/v1/samples/") and path.endswith("/analyze"):
            parts = path.split("/")
            if len(parts) == 6:
                sample_id = parts[4]
                self.handle_sample_analyze(sample_id, body)
                return

        # Route 2: POST /api/v1/analyze
        if path == "/api/v1/analyze":
            content_type = self.headers.get("Content-Type", "")
            self.handle_analyze(body, content_type)
            return

        # Route 3: POST /api/v1/analyses/{analysis_id}/explanations
        if path.startswith("/api/v1/analyses/") and path.endswith("/explanations"):
            parts = path.split("/")
            if len(parts) == 6:
                analysis_id = parts[4]
                self.handle_queue_explanations(analysis_id, body)
                return

        self.send_error_json(404, f"Endpoint not found: {self.path}")

    def handle_sample_analyze(self, sample_id: str, body: bytes) -> None:
        """Run analysis against a known built-in sample scenario."""
        sample_meta = SAMPLE_CATALOG.get(sample_id)
        if not sample_meta:
            self.send_error_json(404, f"Sample scenario '{sample_id}' not found.")
            return

        base_dir = sample_meta["base_dir"]
        sample_paths = [base_dir / f for f in sample_meta["files"]]
        for p in sample_paths:
            if not p.exists():
                self.send_error_json(
                    500, f"Sample file '{p.name}' is missing on server."
                )
                return

        options_data = {}
        if body and body.strip():
            try:
                options_data = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.send_error_json(400, f"Invalid sample analysis JSON: {exc}")
                return
        if not isinstance(options_data, dict):
            self.send_error_json(400, "Sample analysis request must be a JSON object.")
            return
        raw_options = options_data.get("options", options_data)
        try:
            config = _parse_analysis_config(raw_options)
        except ValueError as exc:
            self.send_error_json(400, str(exc))
            return
        try:
            result = analyze_paths(sample_paths, config)
        except Exception as exc:
            self.send_error_json(500, f"Analysis execution error: {exc}")
            return

        analysis_id = "anl_" + hashlib.sha256(os.urandom(16)).hexdigest()[:24]
        stored = StoredAnalysis(
            analysis_id=analysis_id,
            created_at=datetime.now(timezone.utc),
            payload=result.payload,
            events=result.events,
            findings=result.detection_report.findings,
            incidents=result.correlation_report.incidents,
        )

        with _ANALYSES_LOCK:
            _ANALYSES[analysis_id] = stored

        resp = dict(result.payload)
        resp["analysis_id"] = analysis_id
        resp["sample_id"] = sample_id
        self.send_json(200, resp)

    def handle_analyze(self, body: bytes, content_type: str) -> None:
        """Handle log analysis via multipart/form-data or application/json."""
        uploaded_files: list[tuple[str, bytes]] = []
        options_data: dict[str, Any] = {}

        if "multipart/form-data" in content_type:
            # Parse multipart message using standard library BytesParser
            try:
                msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(
                    f"Content-Type: {content_type}\r\n\r\n".encode("utf-8") + body
                )
                for part in msg.iter_parts():
                    name = part.get_param("name", header="content-disposition")
                    filename = part.get_filename()
                    payload = part.get_payload(decode=True)
                    if not payload:
                        continue

                    if name == "options":
                        try:
                            options_data = json.loads(payload.decode("utf-8"))
                        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                            self.send_error_json(400, f"Invalid multipart options JSON: {exc}")
                            return
                        if not isinstance(options_data, dict):
                            self.send_error_json(400, "Multipart options must be a JSON object.")
                            return
                    elif name in {"files", "file"} or filename:
                        if not _supported_upload_name(filename):
                            self.send_error_json(400, f"Unsupported upload format: {filename!r}.")
                            return
                        safe_name = sanitize_filename(
                            filename, default_stem=f"file_{len(uploaded_files)+1}"
                        )
                        uploaded_files.append((safe_name, payload))
            except Exception as exc:
                self.send_error_json(400, f"Failed to parse multipart form data: {exc}")
                return
        else:
            # JSON upload
            try:
                parsed_json = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.send_error_json(400, f"Invalid JSON body: {exc}")
                return

            if not isinstance(parsed_json, dict):
                self.send_error_json(400, "Analyze request must be a JSON object.")
                return

            if "sample_id" in parsed_json:
                self.handle_sample_analyze(
                    parsed_json["sample_id"],
                    json.dumps(parsed_json.get("options", {})).encode("utf-8"),
                )
                return

            options_data = parsed_json.get("options", {})
            raw_files = parsed_json.get("files", [])
            if not isinstance(options_data, dict):
                self.send_error_json(400, "Analysis options must be a JSON object.")
                return
            if not isinstance(raw_files, list):
                self.send_error_json(400, "The files field must be a list.")
                return
            for item in raw_files:
                if not isinstance(item, dict):
                    self.send_error_json(400, "Each uploaded file must be a JSON object.")
                    return
                raw_name = item.get("name") or item.get("filename")
                if not _supported_upload_name(raw_name):
                    self.send_error_json(400, f"Unsupported upload format: {raw_name!r}.")
                    return
                fname = sanitize_filename(item.get("name") or item.get("filename"))
                content = item.get("content", "")
                if isinstance(content, str):
                    content = content.encode("utf-8")
                else:
                    self.send_error_json(400, "Uploaded file content must be a string.")
                    return
                uploaded_files.append((fname, content))

        if not uploaded_files:
            self.send_error_json(
                400, "No files uploaded. Provide at least one valid log file."
            )
            return

        try:
            config = _parse_analysis_config(options_data)
        except ValueError as exc:
            self.send_error_json(400, str(exc))
            return

        # Stage files in temporary directory and guarantee cleanup
        temp_dir = tempfile.mkdtemp(prefix="trace_verified_upload_")
        temp_paths: list[Path] = []
        try:
            for idx, (filename, content) in enumerate(uploaded_files):
                safe_path = Path(temp_dir) / f"{idx}_{filename}"
                safe_path.write_bytes(content)
                temp_paths.append(safe_path)

            result = analyze_paths(temp_paths, config)

            analysis_id = "anl_" + hashlib.sha256(os.urandom(16)).hexdigest()[:24]
            stored = StoredAnalysis(
                analysis_id=analysis_id,
                created_at=datetime.now(timezone.utc),
                payload=result.payload,
                events=result.events,
                findings=result.detection_report.findings,
                incidents=result.correlation_report.incidents,
            )

            with _ANALYSES_LOCK:
                _ANALYSES[analysis_id] = stored

            resp = dict(result.payload)
            resp["analysis_id"] = analysis_id
            self.send_json(200, resp)
        except Exception as exc:
            self.send_error_json(500, f"Analysis processing error: {exc}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def handle_queue_explanations(self, analysis_id: str, body: bytes) -> None:
        """Enqueue optional local Ollama explanation job in background worker."""
        with _ANALYSES_LOCK:
            stored = _ANALYSES.get(analysis_id)
        if not stored:
            self.send_error_json(404, f"Analysis '{analysis_id}' not found.")
            return

        max_explain = 3
        timeout_seconds = DEFAULT_EXPLANATION_TIMEOUT_SECONDS
        if body and body.strip():
            try:
                opts = json.loads(body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self.send_error_json(400, f"Invalid explanation options JSON: {exc}")
                return
            if not isinstance(opts, dict):
                self.send_error_json(400, "Explanation options must be a JSON object.")
                return
            try:
                if "max_explain" in opts:
                    max_explain = max(0, int(opts["max_explain"]))
                if "explain_timeout" in opts:
                    timeout_seconds = max(1.0, float(opts["explain_timeout"]))
            except (TypeError, ValueError, OverflowError) as exc:
                self.send_error_json(400, f"Invalid explanation options: {exc}")
                return

        with _ANALYSES_LOCK:
            if stored.job_status in {"queued", "running"}:
                self.send_json(
                    202, {"analysis_id": analysis_id, "job_status": stored.job_status}
                )
                return
            stored.job_status = "queued"
            stored.job_error = None

        ensure_worker_started()
        _EXPLANATION_QUEUE.put((analysis_id, max_explain, timeout_seconds))

        self.send_json(202, {"analysis_id": analysis_id, "job_status": "queued"})

    def serve_static_file(self, req_path: str) -> None:
        """Serve static web assets strictly confined to WEB_DIR."""
        rel_path = req_path.lstrip("/")
        if not rel_path or rel_path == "index.html":
            target = WEB_DIR / "index.html"
        else:
            target = WEB_DIR / rel_path

        try:
            resolved = target.resolve()
        except Exception:
            self.send_error_json(404, "File not found.")
            return

        # Security check: strictly prevent directory traversal outside WEB_DIR
        try:
            resolved.relative_to(WEB_DIR.resolve())
        except ValueError:
            self.send_error_json(403, "Access denied.")
            return

        if not WEB_DIR.exists():
            if not rel_path or rel_path == "index.html":
                # Milestone 1: Return clean placeholder when web/ folder is not yet populated
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                html = (
                    "<!DOCTYPE html><html><head><title>TRACE-Verified Server</title></head>"
                    "<body style='background:#080c14;color:#94a3b8;font-family:sans-serif;padding:3rem;'>"
                    "<h2 style='color:#38bdf8;'>TRACE-Verified Server v0.1.0</h2>"
                    "<p>Deterministic SOC analysis engine is running on loopback.</p>"
                    "<p>API health: <a style='color:#60a5fa;' href='/api/v1/health'>/api/v1/health</a></p>"
                    "</body></html>"
                )
                self.wfile.write(html.encode("utf-8"))
                return
            self.send_error_json(404, "File not found.")
            return

        if not resolved.is_file():
            self.send_error_json(404, "File not found.")
            return

        mime_type, _ = mimetypes.guess_type(str(resolved))
        if not mime_type:
            mime_type = "application/octet-stream"

        content = resolved.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", f"{mime_type}; charset=utf-8" if "text" in mime_type or "javascript" in mime_type or "json" in mime_type else mime_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(content)

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress default console access logs to keep stdout clean unless debugging."""
        if os.environ.get("TRACE_DEBUG"):
            super().log_message(format, *args)


class SOCServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def create_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> SOCServer:
    """Create and configure the local SOC server bound to loopback only."""
    if host.lower() == "localhost":
        ip = ipaddress.ip_address("127.0.0.1")
    else:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError(f"Host '{host}' is invalid. TRACE-Verified must bind to 127.0.0.1.") from exc

    if not ip.is_loopback:
        raise ValueError(f"Host '{host}' is not a loopback address. TRACE-Verified must bind to 127.0.0.1.")

    ensure_worker_started()
    server = SOCServer((host, port), SOCHandler)
    return server


def run_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> int:
    """Start the server and handle graceful termination."""
    try:
        server = create_server(host, port)
    except Exception as exc:
        print(f"Error initializing server: {exc}", file=sys.stderr)
        return 1

    actual_port = server.server_address[1]
    print(f"TRACE-Verified SOC Server running at http://{host}:{actual_port}/")
    print(f"Engine: Deterministic Offline Analysis (Loopback Only)")
    print(f"Press Ctrl+C to stop.")

    def handle_signal(sig, frame):
        print("\nShutting down server gracefully...")
        threading.Thread(target=server.shutdown).start()

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        server.serve_forever()
    finally:
        server.server_close()
        print("Server stopped.")
    return 0


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="TRACE-Verified SOC Server")
    parser.add_argument("--host", default=DEFAULT_HOST, help="Loopback host to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to listen on (default: 8000)")
    args = parser.parse_args()

    sys.exit(run_server(host=args.host, port=args.port))
