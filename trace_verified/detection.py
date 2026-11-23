"""Small deterministic event detectors; no external services or inference."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterable

from .ingestion import normalize_source_ip, normalize_user
from .schemas import CanonicalEvent, Severity


@dataclass(frozen=True, slots=True)
class DetectionConfig:
    auth_window: timedelta = timedelta(minutes=10)
    brute_force_threshold: int = 5
    spray_account_threshold: int = 5
    success_after_failures_threshold: int = 5
    max_encoded_command_chars: int = 65536
    expected_privilege_actors: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.auth_window <= timedelta(0):
            raise ValueError("detection windows must be positive")
        if min(self.brute_force_threshold, self.spray_account_threshold, self.success_after_failures_threshold) < 2:
            raise ValueError("detection thresholds must be at least 2")
        if self.max_encoded_command_chars < 1:
            raise ValueError("max_encoded_command_chars must be positive")


@dataclass(slots=True)
class Finding:
    finding_id: str
    detector_id: str
    rule_id: str
    title: str
    description: str
    user: str | None
    host: str | None
    source_ip: str | None
    source_device: str | None
    first_observed: datetime | None
    last_observed: datetime | None
    supporting_event_ids: list[str]
    rationale: list[str]
    limitations: list[str]
    severity_contribution: Severity
    original_command_line: str | None = None
    decoded_command_line: str | None = None
    decode_status: str | None = None
    targeted_users: list[str] = field(default_factory=list)
    privilege_action: str | None = None

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["first_observed"] = self.first_observed.isoformat() if self.first_observed else None
        result["last_observed"] = self.last_observed.isoformat() if self.last_observed else None
        result["severity_contribution"] = self.severity_contribution.value
        return result


@dataclass(slots=True)
class DetectorCoverage:
    detector_id: str
    executed: bool
    reason: str
    candidate_events: int = 0
    skipped_events: int = 0


@dataclass(slots=True)
class DetectionReport:
    findings: list[Finding] = field(default_factory=list)
    coverage: list[DetectorCoverage] = field(default_factory=list)


def _raw(event: CanonicalEvent) -> dict[str, Any]:
    return {str(key).strip().casefold().replace("_", "").replace(" ", ""): value
            for key, value in {**event.raw_record, **event.extras}.items()}


def _value(event: CanonicalEvent, *names: str) -> Any:
    fields = _raw(event)
    for name in names:
        value = fields.get(name.casefold().replace("_", "").replace(" ", ""))
        if value is not None and str(value).strip():
            return value
    return None


def _event_code(event: CanonicalEvent) -> str:
    value = event.event_type or _value(event, "eventid", "event") or ""
    return str(value).strip().casefold().replace(" ", "_")


def _auth_kind(event: CanonicalEvent) -> str | None:
    code = _event_code(event)
    if code in {"4625", "failed_logon", "logon_failed", "authentication_failure", "auth_failure", "login_failed"}:
        return "failure"
    if code in {"4624", "successful_logon", "logon_success", "authentication_success", "auth_success", "login_success"}:
        return "success"
    if code in {"logon", "login", "authentication", "auth"}:
        result = str(_value(event, "result", "outcome", "status", "substatus") or "").strip().casefold()
        if result in {"failure", "failed", "fail", "denied", "0xc000006d", "0xc000006a", "0xc0000064"}:
            return "failure"
        if result in {"success", "successful", "succeeded", "0", "0x0"}:
            return "success"
    return None


def _failure_status_label(event: CanonicalEvent) -> str | None:
    """Translate common Windows logon status/substatus values when supplied."""
    labels = {
        "0xc000006a": "bad_password",
        "0xc0000064": "unknown_account",
        "0xc000006d": "bad_credentials",
        "0xc0000234": "account_locked",
        "0xc0000072": "account_disabled",
        "0xc0000071": "password_expired",
        "0xc000006f": "outside_allowed_hours",
        "0xc0000070": "workstation_restriction",
        "0xc0000193": "account_expired",
    }
    raw = _value(event, "substatus") or _value(event, "status")
    return labels.get(str(raw).strip().casefold()) if raw is not None else None


def _time_number(value: datetime) -> tuple[int, float]:
    """Comparable without assigning a timezone to naive timestamps."""
    if value.tzinfo is not None and value.utcoffset() is not None:
        return 1, value.astimezone(timezone.utc).timestamp()
    seconds = value.toordinal() * 86400 + value.hour * 3600 + value.minute * 60 + value.second + value.microsecond / 1e6
    return 0, seconds


def _ordered(events: Iterable[CanonicalEvent]) -> list[CanonicalEvent]:
    return sorted(events, key=lambda e: (_time_number(e.timestamp) if e.timestamp else (-1, 0), e.event_id))


def _source_device(event: CanonicalEvent) -> str | None:
    """Read Windows WorkstationName as a likely source workstation, not event host."""
    value = _value(event, "workstationname", "workstation", "sourcehostname", "clienthostname")
    return str(value).strip().casefold() if value is not None else None


def _stable_id(rule_id: str, events: Iterable[CanonicalEvent]) -> str:
    material = rule_id + "\0" + "\0".join(sorted({event.event_id for event in events}))
    return "fnd_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def _finding(rule_id: str, title: str, description: str, events: list[CanonicalEvent],
             rationale: list[str], severity: Severity, limitations: list[str] | None = None,
             user: str | None = None, host: str | None = None, source_ip: str | None = None,
             original: str | None = None, decoded: str | None = None, decode_status: str | None = None,
             targeted_users: list[str] | None = None, privilege_action: str | None = None) -> Finding:
    ordered = _ordered(events)
    observed = [event.timestamp for event in ordered if event.timestamp is not None]
    family = {"auth.brute_force": "authentication_failures", "auth.password_spray": "authentication_failures",
              "auth.success_after_failures": "success_after_failures", "privilege.change": "privilege_changes",
              "privilege.removal": "privilege_changes", "process.suspicious": "suspicious_process"}.get(rule_id, rule_id.split(".")[0])
    inferred_user = None if targeted_users else next((e.user for e in ordered if e.user), None)
    return Finding(
        finding_id=_stable_id(rule_id, ordered), detector_id=family, rule_id=rule_id,
        title=title, description=description, user=user if user is not None else inferred_user,
        host=host if host is not None else next((e.host for e in ordered if e.host), None),
        source_ip=normalize_source_ip(source_ip if source_ip is not None else next((e.source_ip for e in ordered if e.source_ip), None)),
        source_device=next((_source_device(e) for e in ordered if _source_device(e)), None),
        first_observed=observed[0] if observed else None, last_observed=observed[-1] if observed else None,
        supporting_event_ids=[event.event_id for event in ordered], rationale=rationale,
        limitations=limitations or [], severity_contribution=severity, original_command_line=original,
        decoded_command_line=decoded, decode_status=decode_status,
        targeted_users=sorted(set(targeted_users or [])), privilege_action=privilege_action)


def _qualifying_window(indices: list[int], times: list[float], window: float, threshold: int) -> list[int]:
    """Return the densest qualifying window using a linear scan."""
    left = 0
    best_left = best_right = -1
    for right, moment in enumerate(times):
        while left <= right and moment - times[left] > window:
            left += 1
        if right - left + 1 >= threshold and (best_right < 0 or right - left > best_right - best_left):
            best_left, best_right = left, right
    return indices[best_left:best_right + 1] if best_right >= 0 else []


def _group_time(events: Iterable[CanonicalEvent], key_fn: Callable[[CanonicalEvent], tuple[Any, ...]]) -> dict[tuple[Any, ...], list[CanonicalEvent]]:
    groups: dict[tuple[Any, ...], list[CanonicalEvent]] = defaultdict(list)
    for event in events:
        if event.timestamp is not None:
            # Keep aware and naive datetimes in separate timelines.
            key = key_fn(event) + (event.timestamp.tzinfo is not None and event.timestamp.utcoffset() is not None,)
            groups[key].append(event)
    for group in groups.values():
        group.sort(key=lambda event: (_time_number(event.timestamp), event.event_id))
    return groups


def _auth_detectors(events: list[CanonicalEvent], config: DetectionConfig) -> tuple[list[Finding], list[DetectorCoverage]]:
    findings: list[Finding] = []
    auth_events = [event for event in events if _auth_kind(event)]
    usable = [event for event in auth_events if event.user and event.timestamp]
    skipped = len(auth_events) - len(usable)
    coverage: list[DetectorCoverage] = []
    if not usable:
        reason = "No recognized authentication event types with user and timestamp; input may omit authentication audit fields."
        return findings, [
            DetectorCoverage("authentication_failures", False, reason, 0, skipped or len(events)),
            DetectorCoverage("success_after_failures", False, "No authentication events with sufficient account/time context.", 0, skipped or len(events)),
        ]
    coverage.append(DetectorCoverage("authentication_failures", True,
        "Evaluated recognized authentication events with user and timestamp; incomplete rows are counted as skipped.", len(usable), skipped))
    failures = [event for event in usable if _auth_kind(event) == "failure"]

    by_account = _group_time(failures, lambda event: (event.user or "", event.host or ""))
    for (user, host, _aware), group in by_account.items():
        # Process timezone-aware partitions independently; timezone state is in the group key.
        times = [_time_number(event.timestamp)[1] for event in group]
        selected = _qualifying_window(list(range(len(group))), times, config.auth_window.total_seconds(), config.brute_force_threshold)
        if selected:
            members = [group[index] for index in selected]
            statuses = sorted({f"{_value(event, 'status') or '(missing)'}/{_value(event, 'substatus') or '(missing)'}" for event in members})
            status_labels = Counter(label for event in members if (label := _failure_status_label(event)))
            findings.append(_finding("auth.brute_force", "Repeated authentication failures",
                f"At least {config.brute_force_threshold} failed attempts targeted the same account and host within {config.auth_window}.", members,
                [f"Recognized {len(members)} failed authentication events in a qualifying time window.", f"Observed status/substatus pairs: {', '.join(statuses)}.",
                 f"Interpreted Windows failure signals: {dict(sorted(status_labels.items())) or '(none recognized)'}"],
                Severity.MEDIUM, ["Repeated failures may result from a mistyped password, stale service credential, or monitoring replay."], user=user or None, host=host or None))

    by_source = _group_time((event for event in failures if normalize_source_ip(event.source_ip) and event.host),
        lambda event: (normalize_source_ip(event.source_ip) or "", event.host or ""))
    for (source_ip, host, _aware), group in by_source.items():
        times = [_time_number(event.timestamp)[1] for event in group]
        left = 0
        account_counts: Counter[str] = Counter()
        best_window: tuple[int, int, tuple[int, int]] | None = None
        for right, moment in enumerate(times):
            while left <= right and moment - times[left] > config.auth_window.total_seconds():
                expired_user = group[left].user
                if expired_user:
                    account_counts[expired_user] -= 1
                    if account_counts[expired_user] == 0:
                        del account_counts[expired_user]
                left += 1
            if group[right].user:
                account_counts[group[right].user] += 1
            if len(account_counts) >= config.spray_account_threshold:
                candidate_quality = (len(account_counts), right - left + 1)
                if best_window is None or candidate_quality > best_window[2]:
                    best_window = (left, right, candidate_quality)
        if best_window is not None:
            left, right, _quality = best_window
            members = group[left:right + 1]
            targets = sorted({event.user for event in members if event.user})
            findings.append(_finding("auth.password_spray", "Authentication attempts across multiple accounts",
                f"One source attempted authentication against {len(targets)} accounts on the same host within {config.auth_window}.", members,
                [f"Observed {len(targets)} distinct account names and {len(members)} failed attempts in the maximal qualifying window."],
                Severity.HIGH, ["Shared egress, password-manager errors, or an authorized test can produce this pattern."],
                host=host or None, source_ip=source_ip or None, targeted_users=targets))

    # Success following repeated failures requires a user, source IP, and a
    # source-device or target-host match. IP alone never establishes context.
    contextual = [event for event in usable if normalize_source_ip(event.source_ip) and (event.host or _source_device(event))]
    success_coverage = DetectorCoverage(
        "success_after_failures", bool(contextual),
        "Evaluated account, timestamp, source IP, and matching host or source-device context." if contextual else
        "Skipped: success-after-failures requires account, timestamp, source IP, and host or source-device context; IP alone is insufficient.",
        len(contextual), len(usable) - len(contextual))
    coverage.append(success_coverage)
    by_context = _group_time(contextual, lambda event: (event.user or "", normalize_source_ip(event.source_ip) or "", event.host or "", _source_device(event) or ""))
    for (user, source_ip, host, _device, _aware), group in by_context.items():
        failures_before: list[CanonicalEvent] = []
        fail_left = 0
        for position, success in enumerate(group):
            if _auth_kind(success) == "failure":
                failures_before.append(success)
                continue
            if _auth_kind(success) != "success":
                continue
            now = _time_number(success.timestamp)[1]
            while fail_left < len(failures_before) and now - _time_number(failures_before[fail_left].timestamp)[1] > config.auth_window.total_seconds():
                fail_left += 1
            candidate_count = len(failures_before) - fail_left
            if candidate_count >= config.success_after_failures_threshold:
                evidence = failures_before[-config.success_after_failures_threshold:] + [success]
                findings.append(_finding("auth.success_after_failures", "Successful authentication after repeated failures",
                    f"A successful authentication followed {config.success_after_failures_threshold} or more failures for the same account and source context.", evidence,
                    [f"At least {config.success_after_failures_threshold} failures occurred within {config.auth_window}; the supporting IDs include the latest qualifying failures and this success.", f"Context matched account={user}, source_ip={source_ip}, host={host or '(missing)'}, source_device={_device or '(missing)'}"],
                    Severity.HIGH, ["A valid user may have mistyped credentials before a legitimate login."], user=user or None, host=host or None, source_ip=source_ip or None))
    return findings, coverage


_PRIVILEGE_CODES = {"4728", "4729", "4732", "4733", "4756", "4757"}
_PRIVILEGE_WORDS = ("member_added_to_group", "group_membership_added", "group_membership_change", "group_membership_changed", "group_changed", "privilege_assigned", "privilege_added", "privilege_change", "privilege_changed", "added_to_group", "group_member_added")
_PRIVILEGE_REMOVE_WORDS = ("member_removed_from_group", "group_membership_removed", "removed_from_group", "group_member_removed")


def _privilege(events: list[CanonicalEvent], config: DetectionConfig) -> tuple[list[Finding], DetectorCoverage]:
    findings: list[Finding] = []
    candidates = []
    skipped = 0
    for event in events:
        code = _event_code(event)
        phrase = code.replace(" ", "_")
        if code in _PRIVILEGE_CODES or any(word in phrase for word in _PRIVILEGE_WORDS + _PRIVILEGE_REMOVE_WORDS):
            candidates.append(event)
    expected_actors = {normalize_user(actor) for actor in config.expected_privilege_actors if normalize_user(actor)}
    for event in candidates:
        raw_target_user = _value(event, "targetusername", "target_user_name")
        actor = event.actor or _value(event, "subjectusername", "subject_user_name", "subject_user")
        if actor is None and raw_target_user is None:
            actor = event.user
        actor = normalize_user(actor)
        if actor and actor in expected_actors:
            continue
        group = event.target_group or _value(event, "groupname", "group", "targetgroupname")
        if group is None and actor is not None:
            group = raw_target_user
        member = event.target_member or _value(event, "membername", "memberusername")
        is_removal = _event_code(event) in {"4729", "4733", "4757"} or any(word in _event_code(event) for word in _PRIVILEGE_REMOVE_WORDS)
        action = "membership removal" if is_removal else "privilege or group membership change"
        status = _value(event, "status", "substatus", "failurestatus", "failuresubstatus")
        status_evidence = f"Windows status/substatus: {status}." if status is not None else "No Windows status/substatus was supplied."
        rule_id = "privilege.removal" if is_removal else "privilege.change"
        title = "Privilege/group membership removal observed" if is_removal else "Privilege-related addition observed"
        findings.append(_finding(rule_id, title,
            f"Source event indicates a {action}; this is evidence of a change, not proof it was unauthorized.", [event],
            [f"Source event type: {_event_code(event)}.", f"Actor: {actor or '(missing)' }.",
             f"Target group: {group!r}" if group is not None else "No target group was supplied.",
             f"Target member: {member!r}" if member is not None else "No target member was supplied.", status_evidence],
            Severity.HIGH if not is_removal else Severity.LOW,
            ["Authorization cannot be determined without an approved-change baseline or actor policy."],
            user=actor, host=event.host, privilege_action="removal" if is_removal else "addition"))
    reason = "Evaluated source event types for explicit group membership or privilege-change evidence." if candidates else "No recognized privilege-change event types were present; input may not include such audit events."
    return findings, DetectorCoverage("privilege_changes", bool(candidates), reason, len(candidates), skipped)


_SUSPICIOUS_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("powershell_download_cradle", re.compile(r"\b(?:downloadstring|downloadfile|invoke-webrequest|iwr)\b", re.IGNORECASE)),
    ("powershell_obfuscation", re.compile(r"\b(?:frombase64string|invoke-expression|\biex\b)\b", re.IGNORECASE)),
    ("script_host_execution", re.compile(r"\b(?:mshta\.exe|regsvr32\.exe|rundll32\.exe)\b", re.IGNORECASE)),
    ("certutil_download", re.compile(r"\bcertutil(?:\.exe)?\b.*(?:-urlcache|-decode)", re.IGNORECASE)),
    ("windows_local_admin_creation", re.compile(
        r"\b(?:net(?:1)?\s+localgroup\b[^\r\n]*\b(?:administrators|admins)\b[^\r\n]*/add\b|"
        r"add-localgroupmember\b[^\r\n]*\b(?:administrators|admins)\b|"
        r"add-adgroupmember\b[^\r\n]*\bdomain admins\b)", re.IGNORECASE)),
    ("windows_local_account_creation", re.compile(
        r"\b(?:net(?:1)?\s+user\b[^\r\n]*/add\b|new-localuser\b)", re.IGNORECASE)),
    ("credential_dumping", re.compile(
        r"\b(?:sekurlsa::logonpasswords|invoke-mimikatz|mimikatz(?:\.exe)?|"
        r"comsvcs\.dll.{0,80}\bminidump\b|procdump(?:64)?(?:\.exe)?.{0,80}\blsass(?:\.exe)?\b)", re.IGNORECASE)),
    ("reverse_shell", re.compile(
        r"\b(?:new-object\s+(?:(?:system\.)?net\.)?sockets\.tcpclient|"
        r"system\.net\.sockets\.tcpclient|invoke-powershelltcp)\b|/dev/tcp/", re.IGNORECASE)),
)

_HIGH_IMPACT_PROCESS_RULES = {
    "credential_dumping", "reverse_shell", "windows_local_admin_creation", "powershell_download_cradle",
}

_SWITCH_TOKEN = re.compile(r"(?<!\S)([-/][A-Za-z][A-Za-z0-9-]*)(?::([^\s]+))?")
_POWERSHELL_INVOCATION = re.compile(r"(?<![A-Za-z0-9_.-])(?:powershell|pwsh)(?:\.exe)?(?=\s|$)", re.IGNORECASE)


def _encoded_command_argument(text: str) -> str | None:
    """Extract PowerShell EncodedCommand values, including unambiguous prefixes."""
    invocation = _POWERSHELL_INVOCATION.search(text)
    if invocation is None:
        return None
    arguments = text[invocation.end():]
    for match in _SWITCH_TOKEN.finditer(arguments):
        flag = match.group(1).lstrip("-/").casefold()
        is_supported_prefix = flag in {"e", "ec"} or (
            flag.startswith("enc") and "encodedcommand".startswith(flag)
        )
        if is_supported_prefix:
            value = match.group(2)
            if value is None:
                value = arguments[match.end():].lstrip()
                if value.startswith(('"', "'")):
                    quote = value[0]
                    closing = value.find(quote, 1)
                    value = value[1:closing] if closing >= 0 else value[1:]
                else:
                    value = value.split(maxsplit=1)[0] if value else ""
            return value
    return None


def decode_powershell_encoded(value: str, max_chars: int = 65536) -> tuple[str | None, str]:
    if len(value) > max_chars:
        return None, "oversized"
    cleaned = value.strip().strip("\"'")
    if not cleaned or len(cleaned) > max_chars:
        return None, "oversized_or_empty"
    try:
        raw = base64.b64decode(cleaned + "=" * (-len(cleaned) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None, "malformed_base64"
    if len(raw) > max_chars:
        return None, "decoded_value_oversized"
    for encoding in ("utf-16le", "utf-8"):
        try:
            decoded = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if decoded and "\x00" not in decoded:
            return decoded, "decoded"
    return None, "unsupported_text_encoding"


def _process(events: list[CanonicalEvent], config: DetectionConfig) -> tuple[list[Finding], DetectorCoverage]:
    findings: list[Finding] = []
    usable = [event for event in events if event.process or event.command_line]
    skipped = len(events) - len(usable)
    if not usable:
        return findings, DetectorCoverage("suspicious_process", False,
            "No process name or command-line fields were available.", 0, skipped)
    for event in usable:
        text = f"{event.process or ''} {event.command_line or ''}".strip()
        matches = [name for name, pattern in _SUSPICIOUS_PATTERNS if pattern.search(text)]
        encoded_argument = _encoded_command_argument(text)
        decoded = None
        decode_status = None
        decoded_matches: list[str] = []
        if encoded_argument is not None:
            decoded, decode_status = decode_powershell_encoded(encoded_argument, config.max_encoded_command_chars)
            matches.insert(0, "powershell_encoded")
            if decode_status == "decoded":
                decoded_matches = [name for name, pattern in _SUSPICIOUS_PATTERNS if pattern.search(decoded)]
                matches.extend(name for name in decoded_matches if name not in matches)
        if not matches:
            continue
        rationale = [f"Matched rule(s): {', '.join(matches)}.",
                     f"Encoded command decode status: {decode_status}." if decode_status else "No encoded command was present."]
        if decoded is not None:
            rationale.append(f"Decoded command: {decoded}")
        if decoded_matches:
            rationale.append(f"Decoded command matched suspicious rule(s): {', '.join(decoded_matches)}.")
        neutral_encoded = (encoded_argument is not None and not decoded_matches and
                           not (set(matches) - {"powershell_encoded"}))
        content_matches = set(matches) - {"powershell_encoded"}
        if content_matches & _HIGH_IMPACT_PROCESS_RULES:
            severity = Severity.HIGH
        elif neutral_encoded and decode_status == "decoded":
            severity = Severity.LOW
        elif content_matches or encoded_argument is not None:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW
        title = "Encoded PowerShell command observed" if neutral_encoded else "Suspicious process execution pattern"
        description = ("PowerShell EncodedCommand was decoded; no configured suspicious-content rule matched."
                      if neutral_encoded and decode_status == "decoded" else
                      "An encoded PowerShell argument was observed, but decoding did not complete."
                      if neutral_encoded else
                      f"Process command line matched deterministic rule(s): {', '.join(matches)}.")
        findings.append(_finding("process.suspicious", title,
            description, [event],
            rationale, severity,
            ["A legitimate administrative script or scheduled task may use similar command-line options."],
            original=event.command_line, decoded=decoded, decode_status=decode_status))
    return findings, DetectorCoverage("suspicious_process", True,
        "Evaluated available process names and command lines with deterministic local patterns.", len(usable), skipped)


def detect(events: Iterable[CanonicalEvent], config: DetectionConfig | None = None) -> DetectionReport:
    """Run the four detector families and return traceable findings and coverage."""
    config = config or DetectionConfig()
    # A repeated reference to the same source event must not inflate a window.
    by_id: dict[str, CanonicalEvent] = {}
    for event in events:
        by_id.setdefault(event.event_id, event)
    materialized = list(by_id.values())
    auth_findings, auth_coverage = _auth_detectors(materialized, config)
    privilege_findings, privilege_coverage = _privilege(materialized, config)
    process_findings, process_coverage = _process(materialized, config)
    findings = auth_findings + privilege_findings + process_findings
    findings.sort(key=lambda finding: (finding.first_observed is None,
        _time_number(finding.first_observed) if finding.first_observed else (0, 0), finding.rule_id, finding.finding_id))
    return DetectionReport(findings=findings, coverage=[*auth_coverage, privilege_coverage, process_coverage])
