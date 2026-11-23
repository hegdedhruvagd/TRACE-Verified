"""Unit and integration tests for TRACE-Verified standard-library HTTP server."""

import io
import json
import queue
import socket
import threading
from datetime import datetime, timezone
from http.client import HTTPConnection
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from trace_verified.server import (
    DEFAULT_HOST,
    DEFAULT_EXPLANATION_TIMEOUT_SECONDS,
    MAX_UPLOAD_BYTES,
    SAMPLE_CATALOG,
    StoredAnalysis,
    create_server,
    sanitize_filename,
    _ANALYSES,
    _ANALYSES_LOCK,
)
import trace_verified.server as server_module


@pytest.fixture(scope="module")
def live_server():
    """Start a real loopback server on an ephemeral port for HTTP tests."""
    server = create_server(host=DEFAULT_HOST, port=0)
    host, port = server.server_address
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield host, port
    server.shutdown()
    server.server_close()


def test_server_rejects_non_loopback_host():
    """Server must refuse to bind to non-loopback addresses."""
    with pytest.raises(ValueError, match="must bind to 127.0.0.1"):
        create_server(host="192.168.1.100", port=8000)
    with pytest.raises(ValueError, match="must bind to 127.0.0.1"):
        create_server(host="0.0.0.0", port=8000)


def test_sanitize_filename():
    assert sanitize_filename("test.jsonl") == "test.jsonl"
    assert sanitize_filename("../../etc/passwd.jsonl") == "passwd.jsonl"
    assert sanitize_filename("C:\\Windows\\system32\\cmd.csv") == "cmd.csv"
    assert sanitize_filename("malicious.exe") == "malicious.jsonl"
    assert sanitize_filename(None) == "upload.jsonl"
    assert sanitize_filename("") == "upload.jsonl"


def test_health_endpoint(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("GET", "/api/v1/health")
    resp = conn.getresponse()
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert data["status"] == "ok"
    assert data["version"] == "0.1.0"
    assert data["engine"] == "deterministic"
    assert "server_time" in data


def test_ollama_status_offline(live_server):
    """When Ollama is not running, endpoint returns 200 with available=False."""
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("GET", "/api/v1/ollama")
    resp = conn.getresponse()
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert "available" in data
    assert "phi4-mini:latest" in data["configured_model"]


def test_server_ollama_probe_bypasses_proxies_and_refuses_redirects():
    response = MagicMock()
    response.__enter__.return_value = response
    response.read.return_value = b'{"models": [{"name": "phi4-mini:latest"}]}'
    opener = MagicMock()
    opener.open.return_value = response
    with patch("trace_verified.server.build_opener", return_value=opener) as build:
        status = server_module.check_ollama_status()

    assert status["available"] is True
    handlers = build.call_args.args
    assert any(type(handler).__name__ == "ProxyHandler" and handler.proxies == {} for handler in handlers)
    redirect_handler = next(handler for handler in handlers if type(handler).__name__ == "_LocalRedirectRefused")
    assert redirect_handler.redirect_request(None, None, 302, "Found", {}, "http://example.com/") is None
    request = opener.open.call_args.args[0]
    assert request.full_url == "http://127.0.0.1:11434/api/tags"


def test_samples_catalog(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("GET", "/api/v1/samples")
    resp = conn.getresponse()
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    samples = data["samples"]
    sample_ids = {s["id"] for s in samples}
    assert "attack_chain" in sample_ids
    assert "benign" in sample_ids
    assert "prompt_injection" in sample_ids
    assert "windows_audit" in sample_ids


def test_sample_analyze_attack_chain(live_server):
    """Run analysis against the built-in attack_chain sample."""
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/attack_chain/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert data["analysis_id"].startswith("anl_")
    assert len(data["incidents"]) >= 1
    assert data["incidents"][0]["severity"] == "critical"
    assert data["incidents"][0]["score"] == 100
    assert len(data["detector_coverage"]) == 4
    assert len(data["supporting_events"]) >= 5


def test_malformed_sample_reports_skipped_detectors_instead_of_false_coverage(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/malformed_sample/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    assert response.status == 200
    data = json.loads(response.read().decode("utf-8"))
    assert data["incidents"] == []
    assert data["ingestion"]["malformed_rows"] == 1
    assert all(not detector["executed"] for detector in data["detector_coverage"])


def test_sequential_attack_benign_and_multi_incident_analyses_are_independent(live_server):
    host, port = live_server
    reports = []
    for sample_id in ("attack_chain_mshta", "benign", "windows_audit"):
        conn = HTTPConnection(host, port)
        conn.request("POST", f"/api/v1/samples/{sample_id}/analyze", body=b"{}",
                     headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        assert response.status == 200
        reports.append(json.loads(response.read().decode("utf-8")))

    attack, benign, multi = reports
    assert len(attack["incidents"]) == 1
    assert benign["incidents"] == []
    assert len(multi["incidents"]) == 2
    assert len({report["analysis_id"] for report in reports}) == 3
    assert all("supporting_events" in report for report in reports)

    with _ANALYSES_LOCK:
        for report in reports:
            _ANALYSES.pop(report["analysis_id"], None)


def test_sample_analyze_not_found(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/nonexistent_sample/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 404


def test_multipart_analyze_upload(live_server):
    """Upload a synthetic log via standard multipart/form-data."""
    host, port = live_server
    boundary = "----WebKitFormBoundary7MA4YWxkTrZu0gW"
    log_content = (
        '{"timestamp": "2026-04-10T10:00:00Z", "user": "alice", "host": "ws-1", "event_type": "4625", "source_ip": "203.0.113.10"}\n'
        '{"timestamp": "2026-04-10T10:00:01Z", "user": "alice", "host": "ws-1", "event_type": "4625", "source_ip": "203.0.113.10"}\n'
        '{"timestamp": "2026-04-10T10:00:02Z", "user": "alice", "host": "ws-1", "event_type": "4625", "source_ip": "203.0.113.10"}\n'
        '{"timestamp": "2026-04-10T10:00:03Z", "user": "alice", "host": "ws-1", "event_type": "4625", "source_ip": "203.0.113.10"}\n'
        '{"timestamp": "2026-04-10T10:00:04Z", "user": "alice", "host": "ws-1", "event_type": "4625", "source_ip": "203.0.113.10"}\n'
    )
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="options"\r\n\r\n'
        f'{{"correlation_window_minutes": 30}}\r\n'
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="files"; filename="auth_test.jsonl"\r\n'
        f"Content-Type: application/json\r\n\r\n"
        f"{log_content}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")

    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/analyze", body=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    })
    resp = conn.getresponse()
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert data["analysis_id"].startswith("anl_")
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "auth.brute_force"
    assert len(data["incidents"]) == 1
    assert data["incidents"][0]["severity"] == "medium"
    assert data["incidents"][0]["score"] == 40


def test_json_analyze_upload(live_server):
    """Upload log content via direct JSON body."""
    host, port = live_server
    payload = {
        "files": [
            {
                "name": "process.jsonl",
                "content": '{"timestamp": "2026-04-10T10:00:00Z", "user": "alice", "host": "ws-1", "event_type": "process_start", "process": "mshta.exe", "command_line": "mshta.exe sample.hta"}\n',
            }
        ],
        "options": {
            "correlation_window_minutes": 30
        }
    }
    body = json.dumps(payload).encode("utf-8")
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/analyze", body=body, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    resp = conn.getresponse()
    assert resp.status == 200
    data = json.loads(resp.read().decode("utf-8"))
    assert data["analysis_id"].startswith("anl_")
    assert len(data["findings"]) == 1
    assert data["findings"][0]["rule_id"] == "process.suspicious"


def test_analyze_no_files_error(live_server):
    host, port = live_server
    body = b'{"files": []}'
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/analyze", body=body, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    resp = conn.getresponse()
    assert resp.status == 400


@pytest.mark.parametrize("payload", [
    [],
    {"files": {}},
    {"files": ["not-an-object"]},
    {"files": [], "options": []},
    {"files": [{"name": "events.jsonl", "content": "{}\n"}], "options": {"auth_window_minutes": "bad"}},
])
def test_json_analyze_rejects_malformed_request_shapes(live_server, payload):
    host, port = live_server
    body = json.dumps(payload).encode("utf-8")
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/analyze", body=body, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    response = conn.getresponse()
    assert response.status == 400
    assert "error" in json.loads(response.read().decode("utf-8"))


def test_sample_analyze_rejects_malformed_json_options(live_server):
    host, port = live_server
    body = b"[]"
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/benign/analyze", body=body, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    response = conn.getresponse()
    assert response.status == 400
    assert "JSON object" in json.loads(response.read().decode("utf-8"))["error"]


def test_json_upload_rejects_unsupported_extension_instead_of_relabeling_it(live_server):
    host, port = live_server
    body = json.dumps({"files": [{"name": "events.txt", "content": "not a supported log"}]}).encode("utf-8")
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/analyze", body=body, headers={
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    })
    response = conn.getresponse()
    assert response.status == 400
    assert "Unsupported upload format" in json.loads(response.read().decode("utf-8"))["error"]


def test_multipart_upload_rejects_unsupported_extension(live_server):
    host, port = live_server
    boundary = "----traceBoundary"
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="files"; filename="events.exe"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
        "not a supported log\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/analyze", body=body, headers={
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    })
    response = conn.getresponse()
    assert response.status == 400
    assert "Unsupported upload format" in json.loads(response.read().decode("utf-8"))["error"]


def test_negative_content_length_is_rejected_before_reading_body(live_server):
    host, port = live_server
    with socket.create_connection((host, port), timeout=2) as conn:
        conn.settimeout(2)
        conn.sendall(
            b"POST /api/v1/analyze HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: -1\r\n"
            b"Connection: close\r\n\r\n"
        )
        chunks = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks)
    assert b"400 Bad Request" in response
    assert b"must not be negative" in response


def test_upload_size_limit_exceeded(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    huge_length = MAX_UPLOAD_BYTES + 1024
    conn.request("POST", "/api/v1/analyze", body=b"too large", headers={
        "Content-Type": "application/json",
        "Content-Length": str(huge_length),
    })
    resp = conn.getresponse()
    assert resp.status == 413
    data = json.loads(resp.read().decode("utf-8"))
    assert "Payload Too Large" in data["error"]


def test_server_default_explanation_timeout_is_180_seconds(live_server, monkeypatch):
    host, port = live_server
    pending = queue.Queue()
    monkeypatch.setattr(server_module, "_EXPLANATION_QUEUE", pending)
    monkeypatch.setattr(server_module, "ensure_worker_started", lambda: None)

    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/benign/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    assert response.status == 200
    analysis_id = json.loads(response.read().decode("utf-8"))["analysis_id"]

    conn.request("POST", f"/api/v1/analyses/{analysis_id}/explanations", body=b"{}",
                 headers={"Content-Type": "application/json"})
    queued = conn.getresponse()
    assert queued.status == 202
    assert DEFAULT_EXPLANATION_TIMEOUT_SECONDS == 180.0
    assert pending.get_nowait() == (analysis_id, 3, 180.0)

    with _ANALYSES_LOCK:
        _ANALYSES.pop(analysis_id, None)


def test_explanation_queue_rejects_malformed_options_without_queuing(live_server, monkeypatch):
    host, port = live_server
    pending = queue.Queue()
    monkeypatch.setattr(server_module, "_EXPLANATION_QUEUE", pending)
    monkeypatch.setattr(server_module, "ensure_worker_started", lambda: None)

    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/benign/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    analysis_id = json.loads(response.read().decode("utf-8"))["analysis_id"]

    conn.request("POST", f"/api/v1/analyses/{analysis_id}/explanations", body=b"[]",
                 headers={"Content-Type": "application/json"})
    response = conn.getresponse()
    assert response.status == 400
    assert "JSON object" in json.loads(response.read().decode("utf-8"))["error"]
    assert pending.empty()

    with _ANALYSES_LOCK:
        _ANALYSES.pop(analysis_id, None)


def test_background_worker_passes_180_second_timeout_to_explanation_runner(monkeypatch):
    analysis_id = "anl_worker_timeout_test"
    stored = StoredAnalysis(analysis_id, datetime.now(timezone.utc), {}, [], [], [])
    pending = queue.Queue()
    pending.put((analysis_id, 1, 180.0))
    pending.put(None)
    monkeypatch.setattr(server_module, "_EXPLANATION_QUEUE", pending)
    monkeypatch.setattr(server_module, "_ANALYSES", {analysis_id: stored})

    with patch("trace_verified.server._explain_selected", return_value=[]) as explain:
        server_module._explanation_worker()

    assert explain.call_args.kwargs["timeout_seconds"] == 180.0
    assert stored.job_status == "completed"


def test_frontend_timeout_defaults_are_180_seconds():
    project = Path(__file__).resolve().parents[1]
    app_js = (project / "web" / "app.js").read_text(encoding="utf-8")
    index_html = (project / "web" / "index.html").read_text(encoding="utf-8")
    assert "cfgExplainTimeout?.value || 180" in app_js
    assert "CPU inference can take up to 180 seconds" in app_js
    assert 'id="cfg-explain-timeout" value="180"' in index_html
    assert "pollExplanationStatus(analysisId, generation);\n    }, 2500)" in app_js
    polling = app_js.split("async function pollExplanationStatus(analysisId, generation)", 1)[1].split("function renderExplanationTab", 1)[0]
    assert "state.explanationJobStatus === 'completed' || state.explanationJobStatus === 'failed'" in polling


def test_explanation_queuing_and_polling(live_server):
    """Verify background explanation enqueuing and polling flow."""
    host, port = live_server

    # First run deterministic analysis on benign sample
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/attack_chain/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    analysis_data = json.loads(resp.read().decode("utf-8"))
    analysis_id = analysis_data["analysis_id"]

    # Queue explanation
    conn.request("POST", f"/api/v1/analyses/{analysis_id}/explanations",
                 body=json.dumps({"max_explain": 1, "explain_timeout": 5.0}).encode("utf-8"),
                 headers={"Content-Type": "application/json"})
    queue_resp = conn.getresponse()
    assert queue_resp.status == 202
    queue_data = json.loads(queue_resp.read().decode("utf-8"))
    assert queue_data["analysis_id"] == analysis_id
    assert queue_data["job_status"] in {"queued", "running"}

    # Poll status
    conn.request("GET", f"/api/v1/analyses/{analysis_id}/explanations")
    poll_resp = conn.getresponse()
    assert poll_resp.status == 200
    poll_data = json.loads(poll_resp.read().decode("utf-8"))
    assert poll_data["analysis_id"] == analysis_id
    assert poll_data["job_status"] in {"queued", "running", "completed", "failed"}


def test_get_analysis_by_id(live_server):
    host, port = live_server
    # Run analysis
    conn = HTTPConnection(host, port)
    conn.request("POST", "/api/v1/samples/benign/analyze", body=b"{}",
                 headers={"Content-Type": "application/json"})
    init_data = json.loads(conn.getresponse().read().decode("utf-8"))
    analysis_id = init_data["analysis_id"]

    # Retrieve by ID
    conn.request("GET", f"/api/v1/analyses/{analysis_id}")
    resp = conn.getresponse()
    assert resp.status == 200
    retrieved = json.loads(resp.read().decode("utf-8"))
    assert retrieved["analysis_id"] == analysis_id
    assert "incidents" in retrieved
    assert "findings" in retrieved


def test_get_analysis_not_found(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("GET", "/api/v1/analyses/anl_nonexistent123456789012")
    resp = conn.getresponse()
    assert resp.status == 404


def test_static_root_serves_html(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("GET", "/")
    resp = conn.getresponse()
    assert resp.status == 200
    assert "text/html" in resp.getheader("Content-Type")
    content = resp.read().decode("utf-8")
    assert "TRACE-Verified" in content


def test_directory_traversal_blocked(live_server):
    host, port = live_server
    conn = HTTPConnection(host, port)
    conn.request("GET", "/../../pyproject.toml")
    resp = conn.getresponse()
    assert resp.status in {403, 404}


def test_static_serves_css_and_js(live_server):
    host, port = live_server
    # Test CSS
    conn = HTTPConnection(host, port)
    conn.request("GET", "/style.css")
    resp = conn.getresponse()
    assert resp.status == 200
    assert "text/css" in resp.getheader("Content-Type")
    css_content = resp.read().decode("utf-8")
    assert "--bg-core" in css_content

    # Test JS
    conn.request("GET", "/app.js")
    resp = conn.getresponse()
    assert resp.status == 200
    assert "javascript" in resp.getheader("Content-Type")
    js_content = resp.read().decode("utf-8")
    assert "TRACE-Verified" in js_content


