"""Reusable deterministic analysis pipeline for CLI and web adapters."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable, Sequence

from .detection import DetectionConfig, DetectionReport, DetectorCoverage, detect
from .incidents import CorrelationReport, IncidentConfig, correlate_findings
from .ingestion import ingest_files
from .schemas import CanonicalEvent


@dataclass(frozen=True, slots=True)
class AnalysisConfig:
    auth_window: timedelta = timedelta(minutes=10)
    brute_force_threshold: int = 5
    spray_account_threshold: int = 5
    success_threshold: int = 5
    correlation_window: timedelta = timedelta(minutes=30)
    max_incident_duration: timedelta = timedelta(minutes=240)
    max_incident_findings: int = 100
    approved_finding_ids: frozenset[str] = frozenset()
    medium_threshold: int = 25
    high_threshold: int = 50
    critical_threshold: int = 75

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> AnalysisConfig:
        if not data:
            return cls()
        auth_win = data.get("auth_window_minutes")
        corr_win = data.get("correlation_window_minutes")
        max_dur = data.get("max_incident_duration_minutes")
        approved = data.get("approved_finding_ids") or data.get("approved_finding_id") or []
        if isinstance(approved, str):
            approved = [approved]
        return cls(
            auth_window=timedelta(minutes=float(auth_win)) if auth_win is not None else timedelta(minutes=10),
            brute_force_threshold=int(data.get("brute_force_threshold", 5)),
            spray_account_threshold=int(data.get("spray_account_threshold", 5)),
            success_threshold=int(data.get("success_threshold", 5)),
            correlation_window=timedelta(minutes=float(corr_win)) if corr_win is not None else timedelta(minutes=30),
            max_incident_duration=timedelta(minutes=float(max_dur)) if max_dur is not None else timedelta(minutes=240),
            max_incident_findings=int(data.get("max_incident_findings", 100)),
            approved_finding_ids=frozenset(str(x) for x in approved if str(x).strip()),
            medium_threshold=int(data.get("medium_threshold", 25)),
            high_threshold=int(data.get("high_threshold", 50)),
            critical_threshold=int(data.get("critical_threshold", 75)),
        )


@dataclass(slots=True)
class AnalysisResult:
    payload: dict[str, Any]
    events: list[CanonicalEvent]
    detection_report: DetectionReport
    correlation_report: CorrelationReport
    source_rows: list[dict[str, Any]]


def coverage_dict(item: DetectorCoverage) -> dict[str, Any]:
    return {
        "detector_id": item.detector_id,
        "executed": item.executed,
        "reason": item.reason,
        "candidate_events": item.candidate_events,
        "skipped_events": item.skipped_events,
    }


def source_ingestion_dict(source_row: dict[str, Any]) -> dict[str, Any]:
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


def analyze_paths(paths: Sequence[Path | str], config: AnalysisConfig | None = None) -> AnalysisResult:
    """Run multi-file ingestion, detection, and incident correlation.
    
    Returns structured results and the final JSON-serializable report payload.
    """
    config = config or AnalysisConfig()
    events, source_rows = ingest_files(paths)
    coverage_rows = [row["coverage"] for row in source_rows]
    ingestion = {
        "total_rows": sum(row.total_rows for row in coverage_rows),
        "accepted_rows": sum(row.accepted_rows for row in coverage_rows),
        "malformed_rows": sum(row.malformed_rows for row in coverage_rows),
        "warnings": [warning for row in coverage_rows for warning in row.warnings],
        "field_present_rows": {
            field: sum(row.field_present_rows.get(field, 0) for row in coverage_rows)
            for field in {field for row in coverage_rows for field in row.field_present_rows}
        },
    }

    detection_config = DetectionConfig(
        auth_window=config.auth_window,
        brute_force_threshold=config.brute_force_threshold,
        spray_account_threshold=config.spray_account_threshold,
        success_after_failures_threshold=config.success_threshold,
    )
    det_report = detect(events, detection_config)

    incident_config = IncidentConfig(
        correlation_window=config.correlation_window,
        max_incident_duration=config.max_incident_duration,
        max_incident_findings=config.max_incident_findings,
        approved_activity_finding_ids=config.approved_finding_ids,
        medium_threshold=config.medium_threshold,
        high_threshold=config.high_threshold,
        critical_threshold=config.critical_threshold,
    )
    inc_report = correlate_findings(det_report.findings, events, incident_config)

    referenced_event_ids = {
        event_id for finding in det_report.findings for event_id in finding.supporting_event_ids
    }
    referenced_event_ids.update(
        event_id for incident in inc_report.incidents for event_id in incident.supporting_event_ids
    )
    matched_finding_ids = {finding.finding_id for finding in det_report.findings}

    payload: dict[str, Any] = {
        "findings": [finding.to_dict() for finding in det_report.findings],
        "detector_coverage": [coverage_dict(item) for item in det_report.coverage],
        "ingestion": ingestion,
        "source_ingestion": [source_ingestion_dict(row) for row in source_rows],
        "incidents": [incident.to_dict() for incident in inc_report.incidents],
        "duplicate_findings_ignored": inc_report.duplicate_findings_ignored,
        "supporting_events": [event.to_dict() for event in events if event.event_id in referenced_event_ids],
        "approval_warnings": [
            f"Approved finding ID did not match any finding: {finding_id}"
            for finding_id in sorted(set(config.approved_finding_ids) - matched_finding_ids)
        ],
    }

    return AnalysisResult(
        payload=payload,
        events=events,
        detection_report=det_report,
        correlation_report=inc_report,
        source_rows=source_rows,
    )

