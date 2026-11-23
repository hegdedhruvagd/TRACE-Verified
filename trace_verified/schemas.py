"""Canonical dataclasses shared by ingestion, analysis, and reporting.

The CLI currently emits the correlation engine's richer incident report
contract directly. The legacy ``Incident``/``AnalysisReport`` containers below
remain available to Python callers; they are not a second scoring path.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class CanonicalEvent:
    """Normalized event with source values retained for auditability."""

    event_id: str
    raw_sha256: str
    timestamp: datetime | None
    user: str | None
    host: str | None
    event_type: str | None
    source: str
    raw_record: dict[str, Any]
    source_row: int | None = None
    raw_timestamp: Any = None
    process: str | None = None
    command_line: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    extras: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    actor: str | None = None
    target_group: str | None = None
    target_member: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return result


@dataclass(slots=True)
class SeverityBreakdown:
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    unknown: int = 0


@dataclass(slots=True)
class Incident:
    incident_id: str
    title: str
    severity: Severity
    confidence: float
    event_ids: list[str]
    evidence: list[str] = field(default_factory=list)
    explanation: str | None = None
    benign_alternative: str | None = None
    remediation: list[str] = field(default_factory=list)
    verification: "Verification" = field(default_factory=lambda: Verification())


@dataclass(slots=True)
class Verification:
    verified: bool = False
    checks: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class IngestionCoverage:
    total_rows: int = 0
    accepted_rows: int = 0
    malformed_rows: int = 0
    field_present_rows: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AnalysisReport:
    report_id: str
    created_at: datetime
    events: list[CanonicalEvent] = field(default_factory=list)
    incidents: list[Incident] = field(default_factory=list)
    severity_breakdown: SeverityBreakdown = field(default_factory=SeverityBreakdown)
    verification: Verification = field(default_factory=Verification)
    ingestion: IngestionCoverage = field(default_factory=IngestionCoverage)

