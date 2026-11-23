"""Reproducible labeled synthetic detector checks and a local runtime probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .corpus import generate_labeled_scenarios, generate_records
from .detection import DetectionConfig, detect
from .ingestion import normalize_host, normalize_user, parse_timestamp
from .schemas import CanonicalEvent, Severity


FAMILIES = ("authentication_failures", "success_after_failures", "privilege_changes", "suspicious_process")


def _to_events(records: list[dict[str, Any]], source: str) -> list[CanonicalEvent]:
    result = []
    for index, raw in enumerate(records, start=1):
        digest = hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        timestamp, warnings = parse_timestamp(raw.get("timestamp"))
        result.append(CanonicalEvent(
            event_id=f"{source}-{index}", raw_sha256=digest, timestamp=timestamp,
            user=normalize_user(raw.get("user")), host=normalize_host(raw.get("host")),
            event_type=str(raw["event_type"]) if raw.get("event_type") is not None else None,
            source=source, raw_record=raw, raw_timestamp=raw.get("timestamp"),
            process=raw.get("process"), command_line=raw.get("command_line"),
            source_ip=raw.get("source_ip"), destination_ip=raw.get("destination_ip"), warnings=warnings))
    return result


def confusion_matrix(positive: list[bool], predicted: list[bool]) -> dict[str, int]:
    tp = sum(actual and guess for actual, guess in zip(positive, predicted))
    fp = sum(not actual and guess for actual, guess in zip(positive, predicted))
    fn = sum(actual and not guess for actual, guess in zip(positive, predicted))
    tn = sum(not actual and not guess for actual, guess in zip(positive, predicted))
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn}


def evaluate_scenarios() -> dict[str, dict[str, int]]:
    scenarios = generate_labeled_scenarios()
    actual = {family: [] for family in FAMILIES}
    predicted = {family: [] for family in FAMILIES}
    config = DetectionConfig(expected_privilege_actors=frozenset({"approved-admin"}))
    for scenario in scenarios:
        expected = set(scenario["truth"])
        report = detect(_to_events(scenario["records"], str(scenario["case_id"])), config)
        rules = {finding.rule_id for finding in report.findings}
        predicted_values = {
            "authentication_failures": bool(rules & {"auth.brute_force", "auth.password_spray"}),
            "success_after_failures": "auth.success_after_failures" in rules,
            "privilege_changes": "privilege.change" in rules,
            "suspicious_process": any(
                finding.rule_id == "process.suspicious" and finding.severity_contribution != Severity.LOW
                for finding in report.findings
            ),
        }
        for family in FAMILIES:
            actual[family].append(family in expected)
            predicted[family].append(predicted_values[family])
    return {family: confusion_matrix(actual[family], predicted[family]) for family in FAMILIES}


def benchmark(event_count: int) -> dict[str, Any]:
    records = generate_records(event_count, seed=7)
    events = _to_events(records, "benchmark")
    start = time.perf_counter()
    report = detect(events)
    elapsed = time.perf_counter() - start
    return {"events": len(events), "seconds": round(elapsed, 4), "findings": len(report.findings)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--benchmark-events", type=int, default=100_000)
    parser.add_argument("--skip-benchmark", action="store_true")
    args = parser.parse_args(argv)
    output: dict[str, Any] = {"synthetic_scenario_confusion": evaluate_scenarios()}
    if not args.skip_benchmark:
        output["runtime_probe"] = benchmark(args.benchmark_events)
    print(json.dumps(output, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
