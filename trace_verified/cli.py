"""Small command-line entry point for initial ingestion work."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from datetime import timedelta

from .detection import DetectionConfig, detect
from .explainer import ExplanationConfig, deterministic_fallback, explain_incident
from .ingestion import ingest_file, ingest_files
from .incidents import IncidentConfig, correlate_findings
from .pipeline import AnalysisConfig, analyze_paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trace-verified")
    subparsers = parser.add_subparsers(dest="command", required=True)
    ingest_parser = subparsers.add_parser("ingest", help="ingest CSV, JSON, or JSONL")
    ingest_parser.add_argument("input", type=Path)
    ingest_parser.add_argument("--output", type=Path)
    detect_parser = subparsers.add_parser("detect", help="ingest and run deterministic detectors")
    detect_parser.add_argument("input", type=Path)
    detect_parser.add_argument("--output", type=Path)
    detect_parser.add_argument("--auth-window-minutes", type=float, default=10)
    detect_parser.add_argument("--brute-force-threshold", type=int, default=5)
    detect_parser.add_argument("--spray-account-threshold", type=int, default=5)
    detect_parser.add_argument("--success-threshold", type=int, default=5)
    analyze_parser = subparsers.add_parser("analyze", help="detect, correlate, and score incidents")
    analyze_parser.add_argument("input", type=Path, nargs="+")
    analyze_parser.add_argument("--output", type=Path)
    analyze_parser.add_argument("--auth-window-minutes", type=float, default=10)
    analyze_parser.add_argument("--brute-force-threshold", type=int, default=5)
    analyze_parser.add_argument("--spray-account-threshold", type=int, default=5)
    analyze_parser.add_argument("--success-threshold", type=int, default=5)
    analyze_parser.add_argument("--correlation-window-minutes", type=float, default=30)
    analyze_parser.add_argument("--max-incident-duration-minutes", type=float, default=240)
    analyze_parser.add_argument("--max-incident-findings", type=int, default=100)
    analyze_parser.add_argument("--approved-finding-id", action="append", default=[])
    analyze_parser.add_argument("--medium-threshold", type=int, default=25)
    analyze_parser.add_argument("--high-threshold", type=int, default=50)
    analyze_parser.add_argument("--critical-threshold", type=int, default=75)
    analyze_parser.add_argument("--explain", action="store_true",
                                help="add evidence-checked explanations from local Ollama")
    analyze_parser.add_argument("--max-explain", type=int, default=3,
                                help="maximum number of highest-priority incidents to send to local Ollama")
    analyze_parser.add_argument("--explain-timeout", type=float, default=180.0,
                                help="local Ollama request timeout in seconds")
    serve_parser = subparsers.add_parser("serve", help="start local SOC web server")
    serve_parser.add_argument("--host", default="127.0.0.1", help="host to bind (default: 127.0.0.1)")
    serve_parser.add_argument("--port", type=int, default=8000, help="port to listen on (default: 8000)")
    args = parser.parse_args(argv)
    if args.command == "serve":
        from .server import run_server
        return run_server(host=args.host, port=args.port)
    if args.command == "analyze" and args.explain:
        if args.max_explain < 0:
            parser.error("--max-explain must be zero or greater")
        if args.explain_timeout <= 0:
            parser.error("--explain-timeout must be positive")

    if args.command == "ingest":
        events, coverage = ingest_file(args.input)
        report = {
            "events": [event.to_dict() for event in events],
            "ingestion": {
                "total_rows": coverage.total_rows,
                "accepted_rows": coverage.accepted_rows,
                "malformed_rows": coverage.malformed_rows,
                "field_present_rows": coverage.field_present_rows,
                "warnings": coverage.warnings,
            },
        }
        rendered = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.command == "detect":
        events, ingestion = ingest_file(args.input)
        report = detect(events, DetectionConfig(
            auth_window=timedelta(minutes=args.auth_window_minutes),
            brute_force_threshold=args.brute_force_threshold,
            spray_account_threshold=args.spray_account_threshold,
            success_after_failures_threshold=args.success_threshold,
        ))
        payload = {
            "findings": [finding.to_dict() for finding in report.findings],
            "detector_coverage": [_coverage_dict(item) for item in report.coverage],
            "ingestion": {
                "total_rows": ingestion.total_rows,
                "accepted_rows": ingestion.accepted_rows,
                "malformed_rows": ingestion.malformed_rows,
                "warnings": ingestion.warnings,
            },
        }
        rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        return 0
    elif args.command == "analyze":
        config = AnalysisConfig(
            auth_window=timedelta(minutes=args.auth_window_minutes),
            brute_force_threshold=args.brute_force_threshold,
            spray_account_threshold=args.spray_account_threshold,
            success_threshold=args.success_threshold,
            correlation_window=timedelta(minutes=args.correlation_window_minutes),
            max_incident_duration=timedelta(minutes=args.max_incident_duration_minutes),
            max_incident_findings=args.max_incident_findings,
            approved_finding_ids=frozenset(args.approved_finding_id),
            medium_threshold=args.medium_threshold,
            high_threshold=args.high_threshold,
            critical_threshold=args.critical_threshold,
        )
        result = analyze_paths(args.input, config)
        payload = result.payload
        if args.explain:
            if args.output:
                _write_json(args.output, payload)
            explanations = _explain_selected(payload, result.correlation_report.incidents,
                                             result.detection_report.findings, result.events,
                                             max_explain=args.max_explain,
                                             timeout_seconds=args.explain_timeout, output_path=args.output)
            payload["ai_explanations"] = explanations
            if args.output:
                _write_json(args.output, payload)
            else:
                print(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", end="")
        else:
            rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
            if args.output:
                _write_json(args.output, payload)
            else:
                print(rendered, end="")
        if any(row["error"] for row in result.source_rows):
            return 1
        return 0


def _coverage_dict(item):
    return {
        "detector_id": item.detector_id,
        "executed": item.executed,
        "reason": item.reason,
        "candidate_events": item.candidate_events,
        "skipped_events": item.skipped_events,
    }


def _source_ingestion_dict(source_row):
    coverage = source_row["coverage"]
    return {
        "source": source_row["source"],
        "error": source_row["error"],
        "total_rows": coverage.total_rows,
        "accepted_rows": coverage.accepted_rows,
        "malformed_rows": coverage.malformed_rows,
        "field_present_rows": coverage.field_present_rows,
        "warnings": coverage.warnings,
    }


def _write_json(path: Path, payload: dict) -> None:
    """Atomically replace a report so an existing deterministic report survives write errors."""
    rendered = json.dumps(payload, indent=2, ensure_ascii=False) + "\n"
    parent = path.parent if path.parent != Path("") else Path(".")
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", newline="\n", delete=False,
                                         dir=parent, prefix=f".{path.name}.", suffix=".tmp") as handle:
            temporary_name = handle.name
            handle.write(rendered)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name and os.path.exists(temporary_name):
            os.unlink(temporary_name)


def _explain_selected(payload: dict, incidents: list, findings: list, events: list,
                      *, max_explain: int, timeout_seconds: float,
                      output_path: Path | None = None) -> list[dict]:
    """Explain highest-score incidents first; fallback per incident and stop after transport failure."""
    priority = sorted(incidents, key=lambda incident: (-incident.score, incident.incident_id))
    selected = priority[:max_explain]
    config = ExplanationConfig(timeout_seconds=timeout_seconds)
    results: dict[str, dict] = {}
    transport_error: str | None = None

    def record(incident, result) -> None:
        results[incident.incident_id] = result.to_dict()
        payload["ai_explanations"] = [results[item.incident_id] for item in incidents
                                      if item.incident_id in results]
        # Updating after each incident preserves useful progress if the next call fails.
        if output_path:
            _write_json(output_path, payload)

    for incident in selected:
        try:
            result = explain_incident(incident, findings, events, config)
        except Exception as exc:
            result = deterministic_fallback(incident, findings, events,
                                            error=f"Unexpected optional explanation error: {exc}",
                                            error_kind="unexpected_error")
        record(incident, result)
        if result.error_kind == "transport":
            transport_error = result.error or "Local Ollama is unavailable; further model requests stopped."
            break

    for incident in incidents:
        if incident.incident_id in results:
            continue
        if transport_error:
            result = deterministic_fallback(incident, findings, events, error=transport_error,
                                            error_kind="transport")
        else:
            result = deterministic_fallback(incident, findings, events,
                                            error="Not selected because --max-explain limits model requests.",
                                            error_kind="not_selected")
        record(incident, result)
    return [results[incident.incident_id] for incident in incidents]


if __name__ == "__main__":
    raise SystemExit(main())
