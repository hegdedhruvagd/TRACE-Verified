"""Reproducible runtime probe for a large synthetic finding set."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Any

from .detection import Finding
from .incidents import IncidentConfig, correlate_findings
from .schemas import CanonicalEvent, Severity


def benchmark(finding_count: int = 100_000) -> dict[str, Any]:
    if finding_count < 0:
        raise ValueError("finding_count must be non-negative")
    base = datetime(2026, 4, 1, tzinfo=timezone.utc)
    findings = []
    events = []
    for index in range(finding_count):
        finding_id = f"synthetic-finding-{index:07d}"
        event_id = f"synthetic-event-{index:07d}"
        observed = base
        findings.append(Finding(
            finding_id, "authentication_failures", "auth.brute_force", "Synthetic authentication finding",
            "Synthetic workload record", "benchmark-user", "benchmark-host", "192.0.2.20", None,
            observed, observed, [event_id], ["Synthetic benchmark rationale"], [], Severity.LOW))
        events.append(CanonicalEvent(event_id, hashlib.sha256(event_id.encode()).hexdigest(), observed,
            "benchmark-user", "benchmark-host", "4625", "benchmark.jsonl", {}))
    start = time.perf_counter()
    report = correlate_findings(findings, events, IncidentConfig(max_incident_findings=100))
    seconds = time.perf_counter() - start
    return {"findings": finding_count, "incidents": len(report.incidents), "seconds": round(seconds, 4)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", type=int, default=100_000)
    args = parser.parse_args(argv)
    print(json.dumps(benchmark(args.findings), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
