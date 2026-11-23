"""Deterministic finding correlation, attack-stage interpretation, and scoring."""

from __future__ import annotations

import hashlib
import json
from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .detection import Finding, _auth_kind, _source_device
from .ingestion import normalize_host, normalize_source_ip, normalize_user
from .schemas import CanonicalEvent, Severity


@dataclass(frozen=True, slots=True)
class IncidentConfig:
    # Kept under its original name for API/CLI compatibility; now limits the
    # gap between consecutive compatible findings.
    correlation_window: timedelta = timedelta(minutes=30)
    max_incident_duration: timedelta = timedelta(hours=4)
    max_incident_findings: int = 100
    approved_activity_finding_ids: frozenset[str] = frozenset()
    medium_threshold: int = 25
    high_threshold: int = 50
    critical_threshold: int = 75
    successful_authentication_points: int = 5
    severity_points: tuple[tuple[str, int], ...] = (
        ("info", 0), ("unknown", 0), ("low", 20), ("medium", 40), ("high", 60), ("critical", 80),
    )

    def __post_init__(self) -> None:
        if self.correlation_window <= timedelta(0):
            raise ValueError("maximum gap between findings must be positive")
        if self.max_incident_duration <= timedelta(0):
            raise ValueError("max_incident_duration must be positive")
        if self.max_incident_findings < 1:
            raise ValueError("max_incident_findings must be at least 1")
        if not (0 <= self.medium_threshold < self.high_threshold < self.critical_threshold <= 100):
            raise ValueError("severity thresholds must be ordered within 0..100")
        if any(points < 0 or points > 100 for _, points in self.severity_points):
            raise ValueError("severity contribution points must be within 0..100")
        if not 0 <= self.successful_authentication_points <= 100:
            raise ValueError("successful_authentication_points must be within 0..100")


@dataclass(slots=True)
class ScoreItem:
    code: str
    category: str
    points: int
    explanation: str
    finding_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class IncidentTimelineEntry:
    timestamp: datetime | None
    event_ids: list[str]
    finding_ids: list[str]
    description: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["timestamp"] = self.timestamp.isoformat() if self.timestamp else None
        return value


@dataclass(slots=True)
class AttackStage:
    stage_id: str
    observed_at: datetime | None
    finding_ids: list[str]
    event_ids: list[str]
    rationale: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["observed_at"] = self.observed_at.isoformat() if self.observed_at else None
        return value


@dataclass(slots=True)
class FindingCorrelation:
    finding_id: str
    reason: str
    linked_finding_id: str | None = None


@dataclass(slots=True)
class CorrelatedIncident:
    incident_id: str
    title: str
    scoring_notice: str
    severity: Severity
    score: int
    score_breakdown: list[ScoreItem]
    first_observed: datetime | None
    last_observed: datetime | None
    affected_users: list[str]
    affected_hosts: list[str]
    finding_ids: list[str]
    supporting_event_ids: list[str]
    timeline: list[IncidentTimelineEntry]
    attack_stages: list[AttackStage]
    correlation_rationale: list[FindingCorrelation]
    approved_finding_ids: list[str]
    correlation_warnings: list[str]
    missing_evidence: list[str]
    limitations: list[str]
    recommended_next_steps: list[str]

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["severity"] = self.severity.value
        value["first_observed"] = self.first_observed.isoformat() if self.first_observed else None
        value["last_observed"] = self.last_observed.isoformat() if self.last_observed else None
        value["timeline"] = [entry.to_dict() for entry in self.timeline]
        value["attack_stages"] = [stage.to_dict() for stage in self.attack_stages]
        return value


@dataclass(slots=True)
class CorrelationReport:
    incidents: list[CorrelatedIncident]
    duplicate_findings_ignored: int = 0


@dataclass(slots=True)
class _WorkIncident:
    findings: list[Finding]
    rationale: list[FindingCorrelation]
    first_observed: datetime | None = None
    last_observed: datetime | None = None
    last_finding_start: datetime | None = None
    last_finding_end: datetime | None = None
    furthest_covered_end: datetime | None = None
    warnings: list[str] = field(default_factory=list)
    active: bool = True

    @property
    def first(self) -> datetime | None:
        return self.first_observed

    @property
    def last(self) -> datetime | None:
        return self.last_observed

    def include(self, finding: Finding) -> None:
        interval = _finding_interval(finding)
        if interval is None:
            return
        if self.first_observed is None or _time_key(interval[0]) < _time_key(self.first_observed):
            self.first_observed = interval[0]
        if self.last_observed is None or _time_key(interval[1]) > _time_key(self.last_observed):
            self.last_observed = interval[1]
        if (self.furthest_covered_end is None or
                _time_key(interval[1]) > _time_key(self.furthest_covered_end)):
            self.furthest_covered_end = interval[1]
        if self.last_finding_start is None or _time_key(interval[0]) > _time_key(self.last_finding_start):
            self.last_finding_start, self.last_finding_end = interval
        elif _time_key(interval[0]) == _time_key(self.last_finding_start):
            if self.last_finding_end is None or _time_key(interval[1]) > _time_key(self.last_finding_end):
                self.last_finding_end = interval[1]


def _time_key(value: datetime) -> tuple[int, float]:
    if value.tzinfo is not None and value.utcoffset() is not None:
        return 1, value.astimezone(timezone.utc).timestamp()
    seconds = value.toordinal() * 86400 + value.hour * 3600 + value.minute * 60 + value.second + value.microsecond / 1e6
    return 0, seconds


def _time_kind(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() is not None


def _identity_keys(finding: Finding) -> tuple[tuple[str, str, str], ...]:
    user = normalize_user(finding.user)
    if not user:
        return ()
    keys = []
    host = normalize_host(finding.host)
    source_ip = normalize_source_ip(finding.source_ip)
    if host:
        keys.append(("user_host", user, host))
    if source_ip:
        keys.append(("user_source_ip", user, source_ip))
    return tuple(keys)


def _finding_interval(finding: Finding) -> tuple[datetime, datetime] | None:
    start = finding.first_observed or finding.last_observed
    end = finding.last_observed or finding.first_observed
    if start is None or end is None or _time_kind(start) != _time_kind(end):
        return None
    return (start, end) if _time_key(start) <= _time_key(end) else (end, start)


def _finding_timestamp_warning(finding: Finding) -> str:
    start, end = finding.first_observed, finding.last_observed
    if start is not None and end is not None and _time_kind(start) != _time_kind(end):
        return "finding has mixed naive and timezone-aware timestamps; chronology is uncertain and it is isolated"
    return "finding has no comparable timestamp and is isolated"


def _span_status(findings: list[Finding], addition: Finding, max_gap: float,
                 max_duration: float) -> tuple[bool, str | None]:
    intervals = [_finding_interval(finding) for finding in findings]
    new_interval = _finding_interval(addition)
    if new_interval is None or any(interval is None for interval in intervals):
        return False, "timestamp_missing"
    concrete = [interval for interval in intervals if interval is not None]
    if any(_time_kind(interval[0]) != _time_kind(new_interval[0]) for interval in concrete):
        return False, "timezone_kind_mismatch"
    ordered = sorted(concrete + [new_interval], key=lambda item: (_time_key(item[0]), _time_key(item[1])))
    previous_end = ordered[0][1]
    for start, end in ordered[1:]:
        gap = max(0.0, _time_key(start)[1] - _time_key(previous_end)[1])
        if gap > max_gap:
            return False, "maximum_gap_exceeded"
        if _time_key(end)[1] > _time_key(previous_end)[1]:
            previous_end = end
    earliest = ordered[0][0]
    latest = max((interval[1] for interval in ordered), key=_time_key)
    if _time_key(latest)[1] - _time_key(earliest)[1] > max_duration:
        return False, "maximum_duration_exceeded"
    return True, None


def _cached_span_status(work: _WorkIncident, addition: Finding, max_gap: float,
                        max_duration: float) -> tuple[bool, str | None]:
    new_interval = _finding_interval(addition)
    if new_interval is None or work.first is None or work.last is None or work.furthest_covered_end is None:
        return False, "timestamp_missing"
    if _time_kind(work.first) != _time_kind(new_interval[0]):
        return False, "timezone_kind_mismatch"
    gap = max(0.0, _time_key(new_interval[0])[1] - _time_key(work.furthest_covered_end)[1])
    if gap > max_gap:
        return False, "maximum_gap_exceeded"
    earliest = work.first if _time_key(work.first) <= _time_key(new_interval[0]) else new_interval[0]
    latest = work.last if _time_key(work.last) >= _time_key(new_interval[1]) else new_interval[1]
    if _time_key(latest)[1] - _time_key(earliest)[1] > max_duration:
        return False, "maximum_duration_exceeded"
    return True, None


def _distance(left: datetime, right: datetime) -> float:
    if _time_kind(left) != _time_kind(right):
        return float("inf")
    a, b = _time_key(left)[1], _time_key(right)[1]
    return max(0.0, max(a, b) - min(a, b))


def _finding_sort_key(finding: Finding) -> tuple[object, ...]:
    interval = _finding_interval(finding)
    if interval is None:
        return (2, 0.0, finding.finding_id)
    return (*_time_key(interval[0]), finding.finding_id)


def _canonical_duplicates(findings: Iterable[Finding]) -> tuple[list[Finding], int]:
    chosen: dict[str, Finding] = {}
    fingerprints: dict[str, str] = {}
    seen = 0
    for finding in findings:
        if finding.finding_id in chosen:
            seen += 1
            current = chosen[finding.finding_id]
            current_encoded = fingerprints.setdefault(
                finding.finding_id,
                json.dumps(current.to_dict(), sort_keys=True, ensure_ascii=False, default=str),
            )
            encoded = json.dumps(finding.to_dict(), sort_keys=True, ensure_ascii=False, default=str)
            if encoded < current_encoded:
                chosen[finding.finding_id] = finding
                fingerprints[finding.finding_id] = encoded
        else:
            chosen[finding.finding_id] = finding
    unique = list(chosen.values())
    unique.sort(key=_finding_sort_key)
    return unique, seen


def _spray_bridge_key(user: str | None, host: str | None, source_ip: str | None) -> tuple[str, str, str] | None:
    normalized_user = normalize_user(user)
    normalized_host = normalize_host(host)
    normalized_ip = normalize_source_ip(source_ip)
    if normalized_user and normalized_host and normalized_ip:
        return normalized_user, normalized_host, normalized_ip
    return None


_SPLIT_REASONS = {
    "timestamp_missing": "could not correlate because one or both findings lack usable timestamps",
    "timezone_kind_mismatch": "did not correlate naive and timezone-aware timestamps; their relationship is uncertain",
    "maximum_gap_exceeded": "split because the maximum gap between consecutive findings was exceeded",
    "maximum_duration_exceeded": "split because the maximum total incident duration was exceeded",
    "maximum_size_exceeded": "split because the configured maximum finding count was reached",
}


def correlate_findings(findings: Iterable[Finding], events: Iterable[CanonicalEvent] = (),
                       config: IncidentConfig | None = None) -> CorrelationReport:
    """Greedily correlate findings through user+host or user+source-IP keys.

    Each finding can create or join an incident. Time and size caps apply before
    adding a finding. A shared IP without a matching user is never a key.
    """
    config = config or IncidentConfig()
    unique, duplicate_count = _canonical_duplicates(findings)
    works: list[_WorkIncident] = []
    latest_by_key: dict[tuple[str, str, str], int] = {}
    spray_targets: dict[tuple[str, str, str], int] = {}
    max_gap = config.correlation_window.total_seconds()
    max_duration = config.max_incident_duration.total_seconds()

    for finding in unique:
        keys = _identity_keys(finding)
        interval = _finding_interval(finding)
        candidates = {latest_by_key[key] for key in keys if key in latest_by_key and works[latest_by_key[key]].active}
        # A multi-account spray may connect to a later success only for an
        # explicitly targeted account and matching source IP + destination host.
        if finding.rule_id == "auth.success_after_failures":
            spray_key = _spray_bridge_key(finding.user, finding.host, finding.source_ip)
            if spray_key in spray_targets and works[spray_targets[spray_key]].active:
                candidates.add(spray_targets[spray_key])
        candidates = sorted(candidates)
        eligible = []
        rejected_reasons: dict[int, str] = {}
        for index in candidates:
            work = works[index]
            fits, reject_reason = _cached_span_status(work, finding, max_gap, max_duration)
            if len(work.findings) < config.max_incident_findings and fits:
                eligible.append(index)
            else:
                rejected_reasons[index] = "maximum_size_exceeded" if len(work.findings) >= config.max_incident_findings else (reject_reason or "maximum_duration_exceeded")

        if not eligible:
            index = len(works)
            split_notes = [_SPLIT_REASONS[reason] for reason in sorted(set(rejected_reasons.values()))]
            start_reason = ("Started a separate incident; " + "; ".join(split_notes) + ".") if split_notes else (
                "Started a separate incident; no compatible earlier finding shared the required identity." if keys or finding.rule_id == "auth.password_spray" else
                "Kept isolated because strong identity fields were unavailable.")
            new_work = _WorkIncident(
                [finding],
                [FindingCorrelation(
                    finding.finding_id,
                    start_reason,
                )],
            )
            new_work.include(finding)
            new_work.warnings.extend(split_notes)
            if interval is None:
                new_work.warnings.append(_finding_timestamp_warning(finding))
            works.append(new_work)
        else:
            # Bridge two candidate incidents only when their combined span and
            # size also fit. A finding can have at most two identity keys.
            mergeable = eligible[:]
            target = mergeable[0]
            for other in mergeable[1:]:
                combined: list[Finding] = []
                for member in works[target].findings + works[other].findings + [finding]:
                    if all(existing.finding_id != member.finding_id for existing in combined):
                        combined.append(member)
                if (len(combined) <= config.max_incident_findings and
                        all(_finding_interval(member) is not None for member in combined) and
                        _span_status(combined[:-1], combined[-1], max_gap, max_duration)[0]):
                    old = works[other]
                    works[target].findings = combined[:-1]
                    ordered_members = sorted(combined[:-1], key=_finding_sort_key)
                    all_intervals = [_finding_interval(member) for member in ordered_members]
                    works[target].first_observed = min((interval[0] for interval in all_intervals if interval), key=_time_key)
                    works[target].last_observed = max((interval[1] for interval in all_intervals if interval), key=_time_key)
                    works[target].last_finding_start, works[target].last_finding_end = _finding_interval(ordered_members[-1])
                    works[target].furthest_covered_end = works[target].last_observed
                    works[target].rationale.extend(old.rationale)
                    works[target].warnings.extend(old.warnings)
                    old.active = False
                    for member in works[target].findings:
                        for identity_key in _identity_keys(member):
                            latest_by_key[identity_key] = target
                        if member.rule_id == "auth.password_spray":
                            for target_user in member.targeted_users:
                                bridge = _spray_bridge_key(target_user, member.host, member.source_ip)
                                if bridge:
                                    spray_targets[bridge] = target
                else:
                    # Prefer the most recent eligible incident if both cannot merge.
                    if _distance(works[other].last, finding.first_observed or finding.last_observed) < _distance(works[target].last, finding.first_observed or finding.last_observed):
                        target = other
            index = target
            chosen_work = works[index]
            matched_key = next((key for key in keys if latest_by_key.get(key) == index), None)
            linked = next((member.finding_id for member in reversed(chosen_work.findings)
                           if matched_key and matched_key in _identity_keys(member)), chosen_work.findings[-1].finding_id)
            if matched_key:
                link_reason = f"Grouped with {linked} by shared {matched_key[0]} identity within {config.correlation_window}."
            elif finding.rule_id == "auth.success_after_failures" and any(
                    member.rule_id == "auth.password_spray" and normalize_user(finding.user) in {normalize_user(user) for user in member.targeted_users}
                    for member in chosen_work.findings):
                link_reason = f"Grouped with {linked} because the spray explicitly targeted this account and source IP+host match."
            else:
                link_reason = f"Grouped with {linked} through a matching user-bound identity key within {config.correlation_window}."
            chosen_work.findings.append(finding)
            chosen_work.include(finding)
            chosen_work.rationale.append(FindingCorrelation(finding.finding_id, link_reason, linked))

        if interval is not None:
            for key in keys:
                latest_by_key[key] = index
        if interval is not None and finding.rule_id == "auth.password_spray" and finding.source_ip and finding.host:
            for target_user in finding.targeted_users:
                bridge = _spray_bridge_key(target_user, finding.host, finding.source_ip)
                if bridge:
                    spray_targets[bridge] = index

    event_map = {event.event_id: event for event in events}
    success_index = _build_success_index(event_map.values())
    incidents = [_build_incident(work, event_map, success_index, config) for work in works if work.active]
    incidents.sort(key=lambda item: (-item.score, _time_key(item.first_observed) if item.first_observed else (2, 0), item.incident_id))
    return CorrelationReport(incidents, duplicate_count)


_STAGE_RANK = {
    "credential_attack": 1,
    "successful_authentication": 2,
    "privilege_change": 3,
    "privilege_removal": 3,
    "multi_host_authentication": 4,
    "suspicious_execution": 5,
    "defense_evasion": 6,
}


def _interpret_stages(findings: list[Finding], successful_events: list[CanonicalEvent] | None = None) -> list[AttackStage]:
    memberships: dict[str, list[Finding]] = {}
    for finding in findings:
        if finding.rule_id in {"auth.brute_force", "auth.password_spray"}:
            memberships.setdefault("credential_attack", []).append(finding)
        elif finding.rule_id == "auth.success_after_failures":
            memberships.setdefault("successful_authentication", []).append(finding)
        elif finding.rule_id == "privilege.change":
            memberships.setdefault("privilege_change", []).append(finding)
        elif finding.rule_id == "privilege.removal":
            memberships.setdefault("privilege_removal", []).append(finding)
        elif (finding.rule_id == "process.suspicious" and
              not (finding.decode_status == "decoded" and finding.severity_contribution == Severity.LOW)):
            memberships.setdefault("suspicious_execution", []).append(finding)

    success_findings = memberships.get("successful_authentication", [])
    successful_events = successful_events or []
    if successful_events and not success_findings:
        memberships["successful_authentication"] = []
    success_hosts_by_user: dict[str, set[str]] = defaultdict(set)
    for finding in success_findings:
        user = normalize_user(finding.user)
        host = normalize_host(finding.host)
        if user and host:
            success_hosts_by_user[user].add(host)
    for event in successful_events:
        user = normalize_user(event.user)
        host = normalize_host(event.host)
        if user and host:
            success_hosts_by_user[user].add(host)
    multi_host_users = {user for user, hosts in success_hosts_by_user.items() if len(hosts) >= 2}
    if multi_host_users:
        memberships["multi_host_authentication"] = [
            finding for finding in success_findings if normalize_user(finding.user) in multi_host_users
        ]

    evasion_findings = []
    for finding in memberships.get("suspicious_execution", []):
        rationale = " ".join(finding.rationale).casefold()
        if ("powershell_obfuscation" in rationale or
                (finding.decode_status == "decoded" and "decoded command matched suspicious rule(s):" in rationale)):
            evasion_findings.append(finding)
    if evasion_findings:
        memberships["defense_evasion"] = evasion_findings

    stages = []
    for stage_id, members in memberships.items():
        ordered = sorted(members, key=_finding_sort_key)
        event_ids = _unique(item for finding in ordered for item in finding.supporting_event_ids)
        stage_success_events = successful_events
        if stage_id == "multi_host_authentication":
            stage_success_events = [event for event in successful_events if normalize_user(event.user) in multi_host_users]
        if stage_id in {"successful_authentication", "multi_host_authentication"}:
            event_ids = _unique(event_ids + [event.event_id for event in stage_success_events])
        if stage_id == "successful_authentication":
            observations = [(finding.last_observed or finding.first_observed) for finding in ordered
                            if finding.last_observed or finding.first_observed]
        else:
            observations = [finding.first_observed for finding in ordered if finding.first_observed]
        observations.extend(event.timestamp for event in stage_success_events if stage_id in {"successful_authentication", "multi_host_authentication"} and event.timestamp)
        observed = min(observations, key=_time_key) if observations else None
        if stage_id == "credential_attack":
            accounts = {
                normalized
                for finding in ordered
                for account in ([finding.user] + finding.targeted_users)
                if (normalized := normalize_user(account))
            }
            if len(accounts) > 1:
                reason = "Repeated failed authentication attempts were detected across multiple distinct accounts."
            elif accounts:
                reason = "Repeated failed authentication attempts were detected for one account."
            else:
                reason = "Repeated failed authentication attempts were detected; account identity was unavailable."
        elif stage_id == "successful_authentication":
            reason = ("A detector finding contains a success following repeated failures for matching account/source context."
                      if ordered else "A raw successful-logon event matched account and source/host context after credential activity.")
        elif stage_id == "privilege_change":
            reason = "A source event explicitly indicated a privilege or group-membership addition."
        elif stage_id == "privilege_removal":
            reason = "A source event explicitly indicated a privilege or group-membership removal; this is not counted as escalation."
        elif stage_id == "multi_host_authentication":
            reason = "The same normalized user has successful-authentication evidence on multiple hosts; this describes observed scope and does not establish lateral movement."
        elif stage_id == "defense_evasion":
            reason = "Suspicious PowerShell encoded or obfuscation evidence supports a defense-evasion stage."
        else:
            reason = "A suspicious process execution finding was observed."
        stages.append(AttackStage(stage_id, observed, [item.finding_id for item in ordered], event_ids, reason))
    stages.sort(key=lambda item: (_time_key(item.observed_at) if item.observed_at else (2, 0), _STAGE_RANK[item.stage_id]))
    return stages


def _unique(values: Iterable[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _score(stages: list[AttackStage], findings: list[Finding], users: list[str], hosts: list[str],
           config: IncidentConfig, raw_success_event_ids: set[str] | None = None) -> tuple[int, Severity, list[ScoreItem]]:
    items: list[ScoreItem] = []
    points_by_severity = dict(config.severity_points)
    credited_event_ids: set[str] = set()
    points_by_rule: dict[str, int] = defaultdict(int)
    severity_total = 0
    ordered_findings = sorted(findings, key=lambda item: (
        -points_by_severity.get(item.severity_contribution.value, 0),
        (*_time_key(_finding_interval(item)[0]),) if _finding_interval(item) else (2, 0.0),
        item.rule_id, item.finding_id,
    ))
    for finding in ordered_findings:
        evidence_ids = set(finding.supporting_event_ids)
        evidence_ids = evidence_ids or {"finding:" + finding.finding_id}
        new_ids = evidence_ids - credited_event_ids
        base_points = points_by_severity.get(finding.severity_contribution.value, 0)
        evidence_points = (base_points * len(new_ids) + len(evidence_ids) - 1) // len(evidence_ids) if new_ids else 0
        # One rule can add at most its strongest configured contribution to an
        # incident. Distinct events remain visible, but repeated alerts do not
        # turn one detector family into an unbounded score multiplier.
        points = min(evidence_points, max(0, base_points - points_by_rule[finding.rule_id]))
        points_by_rule[finding.rule_id] += points
        severity_total += points
        credited_event_ids.update(evidence_ids)
        items.append(ScoreItem(
            "finding_severity:" + finding.finding_id, "detector_severity", points,
            f"{finding.severity_contribution.value.title()} detector contribution ({base_points}) scaled by {len(new_ids)}/{len(evidence_ids)} previously uncredited evidence event(s), with one strongest contribution per rule capped at {base_points}.",
            [finding.finding_id],
        ))
    items.append(ScoreItem("finding_severity_total", "detector_severity", 0,
                           f"Per-finding severity subtotal: {severity_total} points after shared evidence was credited once.",
                           [finding.finding_id for finding in ordered_findings]))

    has_success = any(stage.stage_id == "successful_authentication" for stage in stages)
    success_event_ids = _unique(event_id for stage in stages if stage.stage_id == "successful_authentication" for event_id in stage.event_ids)
    success_points = config.successful_authentication_points if has_success else 0
    items.append(ScoreItem("authentication_outcome", "outcome", success_points,
                           (f"{success_points} points for explicit successful-authentication evidence; failed/blocked attempts receive none."
                            if has_success else
                            "No successful-authentication evidence is linked; failed/blocked attempts receive no success points."),
                           success_event_ids))

    # A stage earns diversity credit only when it contributes evidence not
    # already used for another interpretation (e.g. one encoded process cannot
    # independently count as both execution and evasion).
    credited_stage_findings: set[str] = set()
    credited_stage_events: set[str] = set()
    eligible_stages = []
    for stage in sorted(stages, key=lambda item: (_time_key(item.observed_at) if item.observed_at else (2, 0), _STAGE_RANK[item.stage_id])):
        if stage.stage_id in {"privilege_removal", "multi_host_authentication"}:
            continue
        stage_tokens = (set(stage.event_ids) if stage.event_ids else
                        {"finding:" + finding_id for finding_id in stage.finding_ids})
        new_tokens = stage_tokens - credited_stage_events
        if new_tokens:
            eligible_stages.append(stage)
            credited_stage_findings.update(stage.finding_ids)
            credited_stage_events.update(stage_tokens)
    stage_points = min(15, max(0, len(eligible_stages) - 1) * 5)
    items.append(ScoreItem("stage_diversity", "attack_chain", stage_points,
                           f"{len(eligible_stages)} independently evidenced attack stage(s); 5 points per stage after the first, capped at 15.",
                           _unique(finding_id for stage in eligible_stages for finding_id in stage.finding_ids)))
    forward_steps = 0
    for left, right in zip(eligible_stages, eligible_stages[1:]):
        if (left.observed_at is not None and right.observed_at is not None and
                _time_kind(left.observed_at) == _time_kind(right.observed_at) and
                _time_key(left.observed_at) < _time_key(right.observed_at) and
                _STAGE_RANK[right.stage_id] > _STAGE_RANK[left.stage_id] and
                not (set(left.finding_ids) & set(right.finding_ids)) and
                set(left.event_ids) != set(right.event_ids)):
            forward_steps += 1
    order_points = min(15, forward_steps * 5)
    items.append(ScoreItem("stage_order", "attack_chain", order_points,
                           f"Observed {forward_steps} strictly chronological forward transitions with distinct evidence; 5 points each, capped at 15.",
                           _unique(finding_id for stage in eligible_stages for finding_id in stage.finding_ids)))

    per_user_hosts: dict[str, set[str]] = {}
    for finding in findings:
        user = normalize_user(finding.user)
        host = normalize_host(finding.host)
        if user and host:
            per_user_hosts.setdefault(user, set()).add(host)
    spread = max((len(values) for values in per_user_hosts.values()), default=0)
    spread_points = min(15, max(0, spread - 1) * 5)
    items.append(ScoreItem("host_spread", "scope", spread_points,
                           f"Scope only: maximum {spread} host(s) observed for one normalized user; points are capped at 15, IP alone is not used, and multi-host authentication does not establish lateral movement.",
                           [finding.finding_id for finding in findings if finding.host]))

    raw_success_event_ids = raw_success_event_ids or set()
    if raw_success_event_ids:
        items.append(ScoreItem("raw_success_context", "outcome", 0,
                               "Correlated raw successful-logon events are represented as an evidenced stage; no duplicate outcome points are added.",
                               sorted(raw_success_event_ids)))

    raw_score = sum(item.points for item in items)
    score = min(100, max(0, raw_score))
    if raw_score > 100:
        items.append(ScoreItem("score_cap", "cap", 100 - raw_score, "Score was capped at 100.", []))
    elif raw_score < 0:
        items.append(ScoreItem("score_floor", "cap", -raw_score, "Score was floored at 0.", []))
    if score >= config.critical_threshold:
        severity = Severity.CRITICAL
    elif score >= config.high_threshold:
        severity = Severity.HIGH
    elif score >= config.medium_threshold:
        severity = Severity.MEDIUM
    else:
        severity = Severity.LOW
    return score, severity, items


def _timeline(findings: list[Finding], event_map: dict[str, CanonicalEvent],
              additional_event_ids: list[str] | None = None) -> list[IncidentTimelineEntry]:
    by_event: dict[str, list[Finding]] = {}
    for finding in findings:
        for event_id in finding.supporting_event_ids:
            by_event.setdefault(event_id, []).append(finding)
    referenced = _unique(list(by_event) + (additional_event_ids or []))
    if event_map and any(event_id in event_map for event_id in referenced):
        rows = []
        for event_id in referenced:
            event = event_map.get(event_id)
            matches = by_event.get(event_id, [])
            ids = [finding.finding_id for finding in matches]
            if event is None:
                timestamp = next((finding.first_observed for finding in matches if finding.first_observed), None)
                label = next((finding.title for finding in matches), "Correlated successful-logon context")
            else:
                timestamp = event.timestamp
                label = event.event_type or event.process or "Supporting event"
            rows.append(IncidentTimelineEntry(timestamp, [event_id], ids, str(label)))
        rows.sort(key=lambda row: (_time_key(row.timestamp) if row.timestamp else (2, 0), tuple(row.event_ids)))
        return rows
    rows = [IncidentTimelineEntry(finding.first_observed, list(finding.supporting_event_ids), [finding.finding_id], finding.title)
            for finding in findings]
    for event_id in additional_event_ids or []:
        event = event_map.get(event_id)
        rows.append(IncidentTimelineEntry(event.timestamp if event else None, [event_id], [],
                                          (event.event_type if event else None) or "Correlated successful-logon context"))
    rows.sort(key=lambda row: (_time_key(row.timestamp) if row.timestamp else (2, 0), tuple(row.finding_ids)))
    return rows


def _recommended_steps(stages: list[AttackStage], findings: list[Finding]) -> list[str]:
    rules = {finding.rule_id for finding in findings}
    steps = []
    if rules & {"auth.brute_force", "auth.password_spray", "auth.success_after_failures"}:
        steps.extend(["Confirm the authentication outcome and review account lockout or MFA records.",
                      "Validate the source device and source IP owner with the account owner or network team."])
    if "privilege.change" in rules:
        steps.append("Compare the recorded group or privilege change with an approved change ticket and verify the resulting membership.")
    if "privilege.removal" in rules:
        steps.append("Confirm the recorded privilege or group removal matches an approved offboarding or access-change request.")
    if "process.suspicious" in rules:
        steps.append("Preserve the process command line and collect the executable hash, parent process, and related script or endpoint logs.")
    if not steps:
        steps.append("Validate the supporting event records and confirm the affected account and host with their owner.")
    return _unique(steps)


def _build_success_index(events: Iterable[CanonicalEvent]) -> dict[tuple[str, str, str, bool], tuple[list[float], list[CanonicalEvent]]]:
    building: dict[tuple[str, str, str, bool], list[tuple[float, CanonicalEvent]]] = defaultdict(list)
    for event in events:
        if _auth_kind(event) != "success" or event.timestamp is None:
            continue
        user = normalize_user(event.user)
        if not user:
            continue
        aware = _time_kind(event.timestamp)
        host = normalize_host(event.host)
        source_ip = normalize_source_ip(event.source_ip)
        source_device = _source_device(event)
        if host:
            building[("user_host", user, host, aware)].append((_time_key(event.timestamp)[1], event))
        if source_ip:
            building[("user_source_ip", user, source_ip, aware)].append((_time_key(event.timestamp)[1], event))
        if source_device:
            building[("user_source_device", user, source_device, aware)].append((_time_key(event.timestamp)[1], event))
    index = {}
    for key, records in building.items():
        records.sort(key=lambda item: (item[0], item[1].event_id))
        index[key] = ([item[0] for item in records], [item[1] for item in records])
    return index


def _linked_raw_successes(findings: list[Finding], success_index: dict[tuple[str, str, str, bool], tuple[list[float], list[CanonicalEvent]]],
                         config: IncidentConfig) -> list[CanonicalEvent]:
    if not success_index:
        return []
    credential_findings = [finding for finding in findings
                           if finding.rule_id in {"auth.brute_force", "auth.password_spray", "auth.success_after_failures"}]
    matched: dict[tuple[str, str | None], CanonicalEvent] = {}
    max_gap = config.correlation_window.total_seconds()
    max_duration = config.max_incident_duration.total_seconds()
    for finding in credential_findings:
        interval = _finding_interval(finding)
        if interval is None:
            continue
        aware = _time_kind(interval[0])
        interval_start = _time_key(interval[0])[1]
        failure_end = _time_key(interval[1])[1]
        low = failure_end
        high = min(failure_end + max_gap, interval_start + max_duration)
        users = {normalize_user(finding.user)} - {None}
        users.update(normalize_user(user) for user in finding.targeted_users if normalize_user(user))
        identity_keys = []
        host = normalize_host(finding.host)
        source_ip = normalize_source_ip(finding.source_ip)
        source_device = finding.source_device.strip().casefold() if finding.source_device and finding.source_device.strip() else None
        for user in users:
            if host:
                identity_keys.append(("user_host", user, host, aware))
            if source_ip:
                identity_keys.append(("user_source_ip", user, source_ip, aware))
            if source_device:
                identity_keys.append(("user_source_device", user, source_device, aware))
        for key in identity_keys:
            records = success_index.get(key)
            if not records:
                continue
            times, indexed_events = records
            for event in indexed_events[bisect_left(times, low):bisect_right(times, high)]:
                normalized_user = normalize_user(event.user)
                event_host = normalize_host(event.host)
                event_ip = normalize_source_ip(event.source_ip)
                event_device = _source_device(event)
                # Match the complete detector context. Host is not a fallback
                # when an event's source IP or source device conflicts.
                if (event_host != host or event_ip != source_ip or event_device != source_device):
                    continue
                match_key = (normalized_user or "", event_host)
                prior = matched.get(match_key)
                if prior is None or (event.timestamp, event.event_id) < (prior.timestamp, prior.event_id):
                    matched[match_key] = event
    return sorted({event.event_id: event for event in matched.values()}.values(),
                  key=lambda event: (_time_key(event.timestamp) if event.timestamp else (2, 0), event.event_id))


def _build_incident(work: _WorkIncident, event_map: dict[str, CanonicalEvent],
                    success_index: dict[tuple[str, str, str, bool], tuple[list[float], list[CanonicalEvent]]],
                    config: IncidentConfig) -> CorrelatedIncident:
    findings = sorted(work.findings, key=_finding_sort_key)
    approved_ids = sorted({finding.finding_id for finding in findings} & config.approved_activity_finding_ids)
    scoring_findings = [finding for finding in findings if finding.finding_id not in config.approved_activity_finding_ids]
    successful_events = _linked_raw_successes(scoring_findings, success_index, config)
    stages = _interpret_stages(scoring_findings, successful_events)
    users = sorted({normalize_user(finding.user) for finding in findings if normalize_user(finding.user)} |
                   {normalize_user(user) for finding in findings for user in finding.targeted_users if normalize_user(user)})
    hosts = sorted({host for finding in findings if (host := normalize_host(finding.host))} |
                   {host for event in successful_events if (host := normalize_host(event.host))})
    score, severity, breakdown = _score(stages, scoring_findings, users, hosts, config,
                                        {event.event_id for event in successful_events})
    if approved_ids:
        breakdown.append(ScoreItem(
            "approved_findings_excluded", "approved_activity", 0,
            "Approved findings remain visible for audit/context but contribute no detector severity, attack stage, or scope points.",
            approved_ids,
        ))
    observed = []
    for finding in findings:
        observed.extend(value for value in (finding.first_observed, finding.last_observed) if value is not None)
    observed.extend(event.timestamp for event in successful_events if event.timestamp is not None)
    first = min(observed, key=_time_key) if observed else None
    last = max(observed, key=_time_key) if observed else None
    finding_ids = sorted(finding.finding_id for finding in findings)
    incident_id = "inc_" + hashlib.sha256("\0".join(finding_ids).encode("utf-8")).hexdigest()[:24]
    support = _unique([event_id for finding in findings for event_id in finding.supporting_event_ids] +
                      [event.event_id for event in successful_events])
    timeline = _timeline(findings, event_map, [event.event_id for event in successful_events])
    missing = []
    if not users:
        missing.append("No normalized user is available; incident correlation was not possible beyond singleton findings.")
    if not hosts:
        missing.append("No host is available in the findings.")
    if not observed:
        missing.append("No comparable timestamps are available; chronology and time-window correlation could not be verified.")
    unavailable_events = [event_id for event_id in support if event_id not in event_map]
    if unavailable_events:
        missing.append(f"{len(unavailable_events)} supporting event record(s) were not supplied; timeline entries fall back to finding-level timestamps.")
    credential_activity = any(finding.rule_id in {"auth.brute_force", "auth.password_spray"} for finding in scoring_findings)
    if credential_activity and not any(stage.stage_id == "successful_authentication" for stage in stages):
        missing.append("No successful-authentication event could be linked with sufficient identity, source, host, and time context; available incident evidence does not establish whether access succeeded.")
    if any(stage.stage_id == "successful_authentication" for stage in stages) and not any(stage.stage_id == "privilege_change" for stage in stages):
        missing.append("No explicit privilege-change evidence is present in this incident.")
    correlation_warnings = list(work.warnings)
    for event_id in support:
        event = event_map.get(event_id)
        if event and event.timestamp and not _time_kind(event.timestamp):
            correlation_warnings.append("Timezone-naive timestamps were compared as wall-clock values only; their relation to other timezones is uncertain.")
        elif event and event.timestamp is None:
            correlation_warnings.append("At least one supporting event has no parsed timestamp and could not establish chronological correlation.")
        if event:
            correlation_warnings.extend(warning for warning in event.warnings
                                        if "timestamp" in warning.casefold() or "timezone" in warning.casefold())
    correlation_warnings = _unique(correlation_warnings)
    limitations = _unique(limit for finding in findings for limit in finding.limitations)
    stage_names = [stage.stage_id.replace("_", " ") for stage in stages]
    title = "Correlated incident: " + (", ".join(stage_names) if stage_names else findings[0].title)
    return CorrelatedIncident(
        incident_id, title, "Heuristic score for investigation prioritization; not a validated risk model.",
        severity, score, breakdown, first, last, users, hosts,
        finding_ids, support, timeline, stages, work.rationale, approved_ids, correlation_warnings, missing, limitations,
        _recommended_steps(stages, scoring_findings))
