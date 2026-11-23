"""Deterministic CSV, JSON, and JSONL parsing into canonical events."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .schemas import CanonicalEvent, IngestionCoverage


ALIASES: dict[str, tuple[str, ...]] = {
    "timestamp": ("timestamp", "time", "datetime", "event_time", "created_at", "date",
                  "timecreated", "systemtime", "system_time", "time_created"),
    "user": ("user", "username", "targetusername", "target_user_name", "account", "subject_user", "user_name"),
    "actor": ("actor", "subjectusername", "subject_user_name", "subject_user"),
    "target_group": ("target_group", "groupname", "group_name", "targetgroup", "target_group_name"),
    "target_member": ("target_member", "membername", "member_name", "memberusername"),
    "host": ("host", "hostname", "computer", "computer_name", "device"),
    "event_type": ("event_type", "event", "action", "type", "eventid", "event_id"),
    "process": ("process", "process_name", "image", "application"),
    "command_line": ("command_line", "commandline", "cmdline", "process_command_line", "command"),
    "source_ip": ("source_ip", "src_ip", "client_ip", "ip_address", "ipaddress"),
    "destination_ip": ("destination_ip", "dest_ip", "dst_ip", "remote_ip"),
}
CANONICAL_FIELDS = tuple(ALIASES)
def _clean(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_user(value: Any) -> str | None:
    """Normalize case and whitespace without equating UPN/domain aliases."""
    text = _clean(value)
    if text is None:
        return None
    return re.sub(r"\s+", "", text).casefold()


def normalize_host(value: Any) -> str | None:
    """Normalize host casing and a terminal DNS dot; do not shorten FQDNs."""
    text = _clean(value)
    if text is None:
        return None
    return text.rstrip(".").casefold() or None


def normalize_source_ip(value: Any) -> str | None:
    """Normalize source IP text and treat common placeholders as missing."""
    text = _clean(value)
    if text is None:
        return None
    normalized = text.casefold()
    if normalized in {"-", "0.0.0.0", "127.0.0.1", "::1"}:
        return None
    return normalized


def parse_timestamp(value: Any) -> tuple[datetime | None, list[str]]:
    """Parse ISO-8601 timestamps only; naive values get a timezone warning."""
    text = _clean(value)
    if text is None:
        return None, ["timestamp is missing"]
    candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError:
        return None, [f"timestamp could not be parsed as ISO-8601: {text!r}"]
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return parsed, ["timestamp has no timezone; timezone was not assumed"]
    return parsed, []


def _canonicalize(raw: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    normalized_keys = {str(key).strip().casefold(): key for key in raw}
    values: dict[str, Any] = {}
    used: set[Any] = set()
    for field, aliases in ALIASES.items():
        for alias in aliases:
            key = normalized_keys.get(alias.casefold())
            if key is not None:
                values[field] = raw[key]
                used.add(key)
                break
    extras = {str(key): value for key, value in raw.items() if key not in used}
    return values, extras


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def _event(raw: dict[str, Any], source: str, row_number: int) -> CanonicalEvent:
    raw_json = _stable_json(raw)
    raw_hash = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
    identity = f"{source}\0{row_number}\0{raw_hash}".encode("utf-8")
    event_id = "evt_" + hashlib.sha256(identity).hexdigest()[:24]
    values, extras = _canonicalize(raw)
    timestamp, warnings = parse_timestamp(values.get("timestamp"))
    target_group = _clean(values.get("target_group"))
    event_code = _clean(values.get("event_type"))
    if (target_group is None and _clean(values.get("actor")) and
            event_code in {"4728", "4729", "4732", "4733", "4756", "4757"}):
        target_group = _clean(values.get("user"))
    canonical_user = normalize_user(values.get("user"))
    if (event_code in {"4728", "4729", "4732", "4733", "4756", "4757"} and
            target_group is not None and canonical_user == normalize_user(target_group)):
        # Windows group-membership events often put the group in TargetUserName.
        # Keep it in target_group; it is not the affected user account.
        canonical_user = None
    return CanonicalEvent(
        event_id=event_id,
        raw_sha256=raw_hash,
        timestamp=timestamp,
        raw_timestamp=values.get("timestamp"),
        user=canonical_user,
        host=normalize_host(values.get("host")),
        event_type=_clean(values.get("event_type")),
        source=source,
        raw_record=raw,
        source_row=row_number,
        process=_clean(values.get("process")),
        command_line=_clean(values.get("command_line")),
        source_ip=normalize_source_ip(values.get("source_ip")),
        destination_ip=_clean(values.get("destination_ip")),
        extras=extras,
        warnings=warnings,
        actor=normalize_user(values.get("actor")),
        target_group=target_group,
        target_member=_clean(values.get("target_member")),
    )


def _read_rows(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], list[str], int]:
    suffix = path.suffix.casefold()
    malformed: list[str] = []
    rows: list[tuple[int, dict[str, Any]]] = []
    if suffix == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            for line_no, row in enumerate(csv.DictReader(handle), start=2):
                if None in row:
                    malformed.append(f"line {line_no}: extra CSV fields")
                    continue
                rows.append((line_no, dict(row)))
        return rows, malformed, len(rows) + len(malformed)

    if suffix not in {".json", ".jsonl", ".ndjson"}:
        raise ValueError(f"Unsupported input extension: {suffix or '(none)'}")

    text = path.read_text(encoding="utf-8-sig")
    if suffix == ".json":
        payload = json.loads(text)
        items = payload if isinstance(payload, list) else [payload]
        for index, item in enumerate(items, start=1):
            if isinstance(item, dict):
                rows.append((index, item))
            else:
                malformed.append(f"item {index}: expected a JSON object")
        return rows, malformed, len(items)

    total = 0
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        total += 1
        try:
            item = json.loads(line)
        except json.JSONDecodeError as exc:
            malformed.append(f"line {line_no}: invalid JSON ({exc.msg})")
            continue
        if not isinstance(item, dict):
            malformed.append(f"line {line_no}: expected a JSON object")
            continue
        rows.append((line_no, item))
    return rows, malformed, total


def ingest_file(path: str | Path, *, source_name: str | None = None) -> tuple[list[CanonicalEvent], IngestionCoverage]:
    """Read one supported file and return accepted events plus coverage data."""
    file_path = Path(path)
    source = source_name or file_path.name
    rows, malformed, total = _read_rows(file_path)
    events = [_event(row, source, row_no) for row_no, row in rows]
    present = {field: 0 for field in CANONICAL_FIELDS}
    for event in events:
        parsed_values, _ = _canonicalize(event.raw_record)
        for field in CANONICAL_FIELDS:
            present_value = (normalize_source_ip(parsed_values.get(field)) if field == "source_ip"
                             else _clean(parsed_values.get(field)))
            if present_value is not None:
                present[field] += 1
    warnings = [*malformed]
    for event in events:
        if _clean(event.raw_timestamp) is None:
            continue
        warnings.extend(
            f"row {event.source_row}: {warning}"
            for warning in event.warnings
            if "could not be parsed" in warning or "no timezone" in warning
        )
    if not events:
        warnings.append("no valid event rows were found")
    return events, IngestionCoverage(
        total_rows=total,
        accepted_rows=len(events),
        malformed_rows=len(malformed),
        field_present_rows=present,
        warnings=warnings,
    )


def ingest_files(paths: list[str | Path]) -> tuple[list[CanonicalEvent], list[dict[str, Any]]]:
    """Ingest multiple supported files, retaining a coverage/error row per source."""
    events: list[CanonicalEvent] = []
    sources: list[dict[str, Any]] = []
    multi_source = len(paths) > 1
    for raw_path in paths:
        path = Path(raw_path)
        source = str(path)
        try:
            source_label = source if multi_source else path.name
            source_events, coverage = ingest_file(path, source_name=source_label)
            events.extend(source_events)
            error = None
        except (OSError, ValueError, UnicodeError, csv.Error) as exc:
            coverage = IngestionCoverage(malformed_rows=1, warnings=[str(exc)])
            error = str(exc)
        sources.append({"source": source, "coverage": coverage, "error": error})
    return events, sources


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Ingest offline security event files")
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, help="Write JSON report to this path")
    args = parser.parse_args(argv)
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
    output = json.dumps(report, indent=2, ensure_ascii=False, default=str) + "\n"
    if args.output:
        args.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
