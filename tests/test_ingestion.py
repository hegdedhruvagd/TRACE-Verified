from pathlib import Path

from trace_verified.ingestion import ingest_file, ingest_files, normalize_host, normalize_source_ip, normalize_user


FIXTURES = Path(__file__).parent / "fixtures"


def test_csv_aliases_and_raw_values_are_preserved():
    events, coverage = ingest_file(FIXTURES / "windows_aliases.csv")
    assert len(events) == 2
    assert events[0].user == r"contoso\alice"
    assert events[0].raw_record["UserName"] == r"CONTOSO\Alice"
    assert events[0].process == "powershell.exe"
    assert events[0].raw_sha256 and len(events[0].raw_sha256) == 64
    assert coverage.field_present_rows["command_line"] == 1


def test_json_optional_columns_and_naive_timestamp_warning():
    events, coverage = ingest_file(FIXTURES / "optional_missing.json")
    assert len(events) == 2
    assert events[0].extras["custom_field"] == "retained"
    assert events[1].timestamp is not None
    assert any("no timezone" in warning for warning in events[1].warnings)
    assert coverage.field_present_rows["process"] == 0
    assert coverage.field_present_rows["timestamp"] == 2


def test_jsonl_accounts_for_bad_rows():
    events, coverage = ingest_file(FIXTURES / "malformed.jsonl")
    assert len(events) == 2
    assert coverage.total_rows == 3
    assert coverage.accepted_rows == 2
    assert coverage.malformed_rows == 1
    assert "invalid JSON" in coverage.warnings[0]


def test_event_ids_are_stable_and_duplicate_records_remain_distinct(tmp_path):
    sample = tmp_path / "same.jsonl"
    sample.write_text('{"user":"x"}\n{"user":"x"}\n', encoding="utf-8")
    first, _ = ingest_file(sample)
    second, _ = ingest_file(sample)
    assert [event.event_id for event in first] == [event.event_id for event in second]
    assert first[0].raw_sha256 == first[1].raw_sha256
    assert first[0].event_id != first[1].event_id


def test_normalization_does_not_merge_distinct_alias_forms():
    assert normalize_user(r"DOMAIN\Alice") == r"domain\alice"
    assert normalize_user("alice@domain") == "alice@domain"
    assert normalize_user(r"DOMAIN\Alice") != normalize_user("alice@domain")
    assert normalize_host("SERVER.Example.") == "server.example"
    assert normalize_host("server") != normalize_host("server.example")


def test_placeholder_source_ips_are_missing_values():
    for value in (None, "", "  ", "-", "0.0.0.0", "127.0.0.1", "::1"):
        assert normalize_source_ip(value) is None
    assert normalize_source_ip("198.51.100.7") == "198.51.100.7"


def test_placeholder_source_ips_are_missing_in_canonical_events_and_coverage(tmp_path):
    import json

    source = tmp_path / "placeholder-ips.jsonl"
    values = ("-", "0.0.0.0", "127.0.0.1", "::1", "  ")
    source.write_text("\n".join(json.dumps({"source_ip": value, "user": f"user-{i}"})
                                  for i, value in enumerate(values)) + "\n", encoding="utf-8")
    events, coverage = ingest_file(source)
    assert all(event.source_ip is None for event in events)
    assert coverage.field_present_rows["source_ip"] == 0


def test_invocation_path_is_part_of_multi_file_event_provenance_and_ids(tmp_path):
    left = tmp_path / "left" / "same.jsonl"
    right = tmp_path / "right" / "same.jsonl"
    left.parent.mkdir()
    right.parent.mkdir()
    content = '{"timestamp":"2026-05-20T10:00:00Z","user":"alice"}\n'
    left.write_text(content, encoding="utf-8")
    right.write_text(content, encoding="utf-8")

    events, sources = ingest_files([left, right])

    assert len(events) == 2
    assert events[0].source != events[1].source
    assert events[0].event_id != events[1].event_id
    assert events[0].source_row == events[1].source_row == 1
    assert [Path(row["source"]).parent.name for row in sources] == ["left", "right"]


def test_windows_audit_header_aliases_feed_canonical_user_and_source_ip():
    from trace_verified.ingestion import ingest_file

    path = FIXTURES / "windows_audit.json"
    events, _ = ingest_file(path)
    assert events[0].user == r"contoso\alice"
    assert events[0].source_ip == "198.51.100.44"
    assert events[0].event_type == "4625"
    assert events[0].raw_record["Status"] == "0xC000006A"


def test_windows_timecreated_parses_and_preserves_original_value_and_coverage(tmp_path):
    import json

    source = tmp_path / "timecreated.jsonl"
    rows = [
        {"TimeCreated": "not-a-timestamp", "EventID": "4625", "TargetUserName": "CONTOSO\\Alice",
         "Computer": "DC-01", "IpAddress": "192.0.2.44"},
        {"TimeCreated": "2026-05-20T10:15:30", "EventID": "4625", "TargetUserName": "CONTOSO\\Alice",
         "Computer": "DC-01", "IpAddress": "192.0.2.44"},
    ]
    source.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")

    events, coverage = ingest_file(source)

    assert len(events) == coverage.accepted_rows == 2
    assert coverage.malformed_rows == 0
    assert coverage.field_present_rows["timestamp"] == 2
    assert events[0].raw_timestamp == rows[0]["TimeCreated"]
    assert events[0].raw_record["TimeCreated"] == rows[0]["TimeCreated"]
    assert events[0].timestamp is None
    assert any("could not be parsed" in warning for warning in events[0].warnings)
    assert any("could not be parsed" in warning for warning in coverage.warnings)
    assert events[1].timestamp is not None
    assert any("no timezone" in warning for warning in events[1].warnings)
    assert any("no timezone" in warning for warning in coverage.warnings)


def test_ingestion_module_cli_help_smoke():
    import subprocess
    import sys

    result = subprocess.run([sys.executable, "-m", "trace_verified.ingestion", "--help"],
                            capture_output=True, text=True, check=False)
    assert result.returncode == 0
    assert "Ingest offline security event files" in result.stdout
