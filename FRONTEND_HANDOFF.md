# TRACE-Verified Frontend Handoff

This handoff describes the repository as it exists now. The API section is a
proposal; the project currently has a Python CLI and no FastAPI server,
browser-upload route, or frontend.

## 1. Project structure

| Path | Current responsibility |
| --- | --- |
| `trace_verified/ingestion.py` | Reads CSV, JSON, and JSONL/NDJSON files; maps header aliases; creates canonical events, stable event IDs, row/source provenance, field coverage, and timestamp warnings. |
| `trace_verified/schemas.py` | Standard-library dataclasses and the `Severity` enum. `CanonicalEvent` is the ingestion contract. Legacy `Incident` and `AnalysisReport` dataclasses are not the CLI's incident output contract. |
| `trace_verified/detection.py` | Deterministic auth, success-after-failures, explicit privilege/group-change, and suspicious-process detectors; PowerShell EncodedCommand decoding as text; detector coverage and finding records. |
| `trace_verified/incidents.py` | Strong-identity finding correlation, deterministic attack stages, incident timeline, additive heuristic score, severity mapping, and recommended investigative steps. |
| `trace_verified/explainer.py` | Optional localhost-only Ollama adapter, compact incident dossier, structured explanation parsing and bounded verification, and deterministic fallback. |
| `trace_verified/cli.py` | Current executable workflow: `ingest`, `detect`, and multi-file `analyze`; builds the report JSON and optionally adds `ai_explanations`. |
| `trace_verified/corpus.py` | Deterministic synthetic input generator. Its labels are for synthetic evaluation, not a real-world accuracy claim. |
| `trace_verified/evaluate.py`, `trace_verified/incident_evaluate.py` | Synthetic detector and correlation evaluation/scale probes. |
| `scripts/check_ollama.py` | Optional loopback-only Ollama health/model-list check; does not download a model. |
| `tests/fixtures/` | Small CSV, JSON, JSONL, Windows audit, `TimeCreated`, malformed-row, and missing-field examples. |
| `tests/` | Unit and synthetic evaluation tests for ingestion, detectors, incidents, CLI, and local explanation verification. |
| `AI_USAGE.md` | Local-model authority, safety, offline, and verification boundaries. |
| `pyproject.toml` | Python 3.11+, no application dependencies; pytest is an optional pinned development dependency. FastAPI is not currently declared or installed by this project. |

## 2. Actual input and output contracts

### Input files

The CLI accepts these extensions and shapes:

- `.csv`: a header row followed by records; parsing uses `csv.DictReader`.
- `.json`: one JSON object or an array of JSON objects.
- `.jsonl` and `.ndjson`: one JSON object per nonblank line.

For `analyze`, one or more paths can be supplied together. Each file is
ingested independently and retains source-level coverage/provenance. Unknown
extensions or unreadable files are recorded as per-source ingestion errors by
the multi-file path. Malformed rows are counted and reported; valid rows from
the same file can still be analyzed.

Common canonical header aliases in `ingestion.ALIASES` include:

| Canonical field | Examples of accepted headers |
| --- | --- |
| `timestamp` | `timestamp`, `time`, `datetime`, `event_time`, `created_at`, `date`, `TimeCreated`, `SystemTime`, `time_created` |
| `user` | `user`, `username`, `TargetUserName`, `target_user_name`, `account`, `subject_user` |
| `actor` | `actor`, `SubjectUserName`, `subject_user_name`, `subject_user` |
| `target_group` | `target_group`, `GroupName`, `group_name`, `targetgroup` |
| `target_member` | `target_member`, `MemberName`, `member_name`, `memberusername` |
| `host` | `host`, `hostname`, `Computer`, `computer_name`, `device` |
| `event_type` | `event_type`, `event`, `action`, `type`, `EventID`, `event_id` |
| `process` | `process`, `process_name`, `image`, `application` |
| `command_line` | `command_line`, `CommandLine`, `cmdline`, `process_command_line`, `command` |
| `source_ip` | `source_ip`, `src_ip`, `client_ip`, `IpAddress`, `ipaddress` |
| `destination_ip` | `destination_ip`, `dest_ip`, `dst_ip`, `remote_ip` |

Timestamp parsing accepts ISO-8601 using Python's `datetime.fromisoformat`
(including `Z` conversion). A naive timestamp is retained with a warning; no
timezone is guessed. Original row values are retained in `raw_record` and
`raw_timestamp`. User normalization case-folds and removes whitespace but does
not equate domain and UPN aliases. Host normalization case-folds and removes a
terminal DNS dot but does not shorten FQDNs. IP addresses alone are not an
entity/correlation key.

### `CanonicalEvent`

`event.to_dict()` emits these keys; `timestamp` is ISO-8601 text or `null`:

```json
{
  "event_id": "evt_<24 hex characters>",
  "raw_sha256": "<64 hex characters>",
  "timestamp": "2026-05-20T10:15:00+00:00",
  "user": "contoso\\alice",
  "host": "dc-01.contoso.local",
  "event_type": "4625",
  "source": "events.jsonl",
  "raw_record": {"EventID": 4625},
  "source_row": 1,
  "raw_timestamp": "2026-05-20T10:15:00Z",
  "process": null,
  "command_line": null,
  "source_ip": "192.0.2.44",
  "destination_ip": null,
  "extras": {},
  "warnings": [],
  "actor": null,
  "target_group": null,
  "target_member": null
}
```

The event ID is a SHA-256-derived identifier over source label, source row,
and raw-record hash. Preserve it as an opaque evidence key; it can change if
the source label, row position, or input record changes.

### Current CLI commands and arguments

```text
trace-verified ingest INPUT [--output PATH]
trace-verified detect INPUT [--output PATH]
  [--auth-window-minutes 10]
  [--brute-force-threshold 5]
  [--spray-account-threshold 5]
  [--success-threshold 5]
trace-verified analyze INPUT [INPUT ...] [--output PATH]
  [--auth-window-minutes 10]
  [--brute-force-threshold 5]
  [--spray-account-threshold 5]
  [--success-threshold 5]
  [--correlation-window-minutes 30]
  [--max-incident-duration-minutes 240]
  [--max-incident-findings 100]
  [--approved-finding-id FINDING_ID]...
  [--medium-threshold 25] [--high-threshold 50] [--critical-threshold 75]
  [--explain] [--max-explain 3] [--explain-timeout 180]
```

`detect` accepts one input file and does not build incidents. `analyze` accepts
multiple inputs, correlates findings, and writes the report. `--approved-finding-id`
is repeatable. `--explain` is opt-in; the current CLI waits for its selected
local-model requests before returning. The CLI validates `--max-explain >= 0`
and `--explain-timeout > 0`.

### Finding contract

Each finding serializes these exact fields from `detection.Finding`:

```json
{
  "finding_id": "fnd_<24 hex characters>",
  "detector_id": "authentication_failures",
  "rule_id": "auth.brute_force",
  "title": "Repeated authentication failures",
  "description": "Deterministic rule description",
  "user": "contoso\\alice",
  "host": "dc-01.contoso.local",
  "source_ip": "192.0.2.44",
  "source_device": "ws-01",
  "first_observed": "2026-05-20T10:15:00+00:00",
  "last_observed": "2026-05-20T10:15:48+00:00",
  "supporting_event_ids": ["evt_..."],
  "rationale": ["Matched deterministic rule evidence"],
  "limitations": ["A user may have mistyped a password"],
  "severity_contribution": "medium",
  "original_command_line": null,
  "decoded_command_line": null,
  "decode_status": null,
  "targeted_users": [],
  "privilege_action": null
}
```

`first_observed` and `last_observed` are ISO strings or null. The finding
contains a **severity contribution**, not a risk score or confidence field.
The application deterministically owns the finding ID, rule, evidence, and
severity contribution. For encoded PowerShell, the original and decoded text
are separate fields; commands are not executed.

### Detector coverage

Each `detector_coverage` item has:

```json
{
  "detector_id": "authentication_failures",
  "executed": true,
  "reason": "Evaluated recognized authentication events...",
  "candidate_events": 8,
  "skipped_events": 0
}
```

Current detector IDs are `authentication_failures`,
`success_after_failures`, `privilege_changes`, and `suspicious_process`.
`executed: false` is an explicit skipped/not-applicable state with a reason;
the UI must not display it as a verified all-clear.

### Incident, stage, timeline, and scoring contracts

Each `incidents[]` entry comes from `CorrelatedIncident` and has:

```text
incident_id, title, scoring_notice, severity, score, score_breakdown,
first_observed, last_observed, affected_users, affected_hosts, finding_ids,
supporting_event_ids, timeline, attack_stages, correlation_rationale,
approved_finding_ids, correlation_warnings, missing_evidence, limitations,
recommended_next_steps
```

- `severity` is `low`, `medium`, `high`, or `critical` for scored incidents.
- `score` is an integer from 0 to 100. The current default thresholds are
  Low 0–24, Medium 25–49, High 50–74, Critical 75–100; the CLI threshold
  flags can change the cutoffs.
- Every `score_breakdown[]` item is `{code, category, points, explanation,
  finding_ids}`. It explains detector severity, successful authentication,
  distinct evidenced stages/order, host spread, caps, or approved-finding
  exclusions. Scores are heuristic investigation priorities, not validated
  risk probabilities.
- Every `timeline[]` item is `{timestamp, event_ids, finding_ids,
  description}`. Timestamp is ISO text or null; rows are deterministically
  ordered. When the event record is supplied, the description uses its event
  type/process; otherwise it can fall back to a finding description.
- Every `attack_stages[]` item is `{stage_id, observed_at, finding_ids,
  event_ids, rationale}`. Current stage IDs include `credential_attack`,
  `successful_authentication`, `privilege_change`, `privilege_removal`,
  `multi_host_authentication`, `suspicious_execution`, and `defense_evasion`.
  `multi_host_authentication` is explicitly not proof of lateral movement.
- Every `correlation_rationale[]` item is `{finding_id, reason,
  linked_finding_id}`. `linked_finding_id` can be null.
- Incident IDs are stable SHA-256-derived IDs from the sorted correlated
  finding IDs. Incidents are returned in descending score priority, followed
  by observation time and ID for ties.

The score is additive and capped to 0–100. Per-finding severity points use
the configured map (info/unknown 0, low 20, medium 40, high 60, critical 80),
scaled so shared supporting events are credited once and each rule is capped
at its strongest contribution. Explicit successful authentication adds the
configured 5 points; failed/blocked events do not. Distinct independently
evidenced stages and chronological forward transitions add 5-point increments
(each capped at 15). Maximum same-user host spread adds 5 per additional host,
capped at 15. Privilege removal and multi-host authentication do not earn
attack-stage diversity points. Approved finding IDs remain visible but are
excluded from stage interpretation and scoring.

`supporting_event_ids` is the incident's traceability set. Top-level
`supporting_events[]` contains the canonical records referenced by findings
or incidents. Join findings to their event records by `supporting_event_ids`,
and timeline entries by `event_ids`; do not reconstruct or infer evidence.

### Top-level analysis JSON

For `analyze`, the current CLI output has this shape (the array contents use
the contracts above):

```json
{
  "findings": [],
  "detector_coverage": [],
  "ingestion": {
    "total_rows": 0,
    "accepted_rows": 0,
    "malformed_rows": 0,
    "warnings": [],
    "field_present_rows": {}
  },
  "source_ingestion": [
    {
      "source": "path/to/events.jsonl",
      "error": null,
      "total_rows": 0,
      "accepted_rows": 0,
      "malformed_rows": 0,
      "field_present_rows": {},
      "warnings": []
    }
  ],
  "incidents": [],
  "duplicate_findings_ignored": 0,
  "supporting_events": [],
  "approval_warnings": []
}
```

`ingestion` is aggregate coverage across the analyzed inputs. `source_ingestion`
has one entry per path, including source-specific errors. `field_present_rows`
is a count by canonical field. `approval_warnings` reports approved IDs that
did not match any finding. The current analyze CLI still writes its report
when a source has an error, then exits with status 1. `ingest` has `events` and an `ingestion` object;
`detect` has findings, detector coverage, and ingestion coverage but no
incidents.

When `--explain` is present, `ai_explanations[]` is added. Each item has:

```json
{
  "incident_id": "inc_<24 hex characters>",
  "status": "local_model",
  "label": "AI-generated explanation — not evidence",
  "model": "phi4-mini:latest",
  "explanation": {
    "incident_summary": "...",
    "attack_interpretation": "...",
    "evidence_ids": ["evt_..."],
    "alternative_explanations": [],
    "recommended_actions": [],
    "limitations": []
  },
  "error": null,
  "error_kind": null
}
```

The six fields inside `explanation` are the entire model-output schema. The
model cannot add findings or write the deterministic incident fields.
`status` is `local_model`, `deterministic_fallback`, or
`rejected_by_verification`. Fallback entries can have `error_kind` such as
`transport`, `verification`, `request`, `unexpected_error`, or `not_selected`.
There is one result per incident when explain mode is enabled, including
fallback entries for incidents excluded by `--max-explain`. With no incidents,
the array is empty.

## 3. Current execution workflow

For `trace-verified analyze FILE...` the current CLI performs:

1. `ingest_files` reads each supported path, canonicalizes aliases, retains
   raw records/provenance, and aggregates per-file and total coverage/warnings.
2. `detect` runs the configured deterministic detectors against the
   canonical events and returns findings plus executed/skipped coverage.
3. `correlate_findings` groups related findings using normalized user+host or
   user+source-IP context, applies approved-finding exclusions to scoring and
   stages, links supported successful logons, builds timelines/stages, and
   produces deterministic score/severity/recommendations.
4. The CLI assembles findings, coverage, ingestion, source ingestion,
   incidents, duplicate count, supporting events, and unmatched approval
   warnings.
5. If `--output` is set, the deterministic JSON is atomically written before
   any optional local inference.
6. If `--explain` is set, the CLI selects up to `--max-explain` incidents by
   descending score and calls the local explainer. A timeout/unavailable
   server or rejected response becomes a separate fallback entry; a transport
   failure stops subsequent model requests. The report output is updated as
   explanations finish. The CLI then exits with the deterministic report
   available even when Ollama fails.

The current CLI has no HTTP upload endpoint and no shared web service object;
the `analyze` orchestration/report assembly currently lives in `cli.py`.

## 4. Proposed smallest practical FastAPI adapter

Keep the browser UI and API same-origin and local. The adapter should stage
each uploaded file under a server-generated temporary name with its validated
extension, pass those paths to `ingest_files`, and delete the files after
parsing. Never trust the client's path or join it into a filesystem path.
Extracting a small reusable `analyze_paths(paths, config)` orchestration
function for both CLI and API would avoid duplicating report assembly; it
should call the existing ingestion, detection, and correlation functions
without moving their authority into the web layer.

Suggested endpoints (proposed only):

### `POST /api/v1/analyze`

`multipart/form-data` with repeated `files` parts and an `options` JSON form
field. Example options:

```json
{
  "auth_window_minutes": 10,
  "brute_force_threshold": 5,
  "spray_account_threshold": 5,
  "success_threshold": 5,
  "correlation_window_minutes": 30,
  "max_incident_duration_minutes": 240,
  "max_incident_findings": 100,
  "approved_finding_ids": []
}
```

On success, return the current analysis JSON keys directly, plus an
adapter-owned opaque `analysis_id` for local result/job lookup. The existing
report keys and values remain the source of truth; the ID is not a replacement
for deterministic `incident_id`s.

Example request description:

```text
POST /api/v1/analyze
Content-Type: multipart/form-data
files=@auth.jsonl
files=@endpoint.csv
options={"correlation_window_minutes":30}
```

### `POST /api/v1/analyses/{analysis_id}/explanations`

Queue optional explanation work after deterministic analysis has already
returned. Accept a bounded `max_explain` (default 3); return `202 Accepted`:

```json
{"analysis_id":"analysis_<opaque>","job_status":"queued"}
```

The job must use the existing dossier builder, `explain_incident`, and
verifier. A single local worker/queue is preferable for CPU-bound Phi calls;
do not run several concurrent Ollama generations by default.

### `GET /api/v1/analyses/{analysis_id}/explanations`

Poll the explanation job. Example while running:

```json
{"analysis_id":"analysis_<opaque>","job_status":"running","ai_explanations":[]}
```

When completed, `ai_explanations` contains the exact `ExplanationResult`
objects documented above, correlated by `incident_id`. Job status is a
proposed transport wrapper (for example `queued`, `running`, `completed`);
the per-incident `status` continues to use the existing values.

The minimum HTTP errors should be request validation/no files (400 or 422),
unsupported upload extension (422 or a per-source error), and upload size
limit (413). Malformed rows and partial multi-file failures should remain
visible in `ingestion.warnings` and `source_ingestion`; do not discard a
partial report. Ollama failure is not an analysis HTTP failure: complete the
job with deterministic fallbacks and an explicit per-incident transport
status. Keep report/job storage bounded and temporary; do not persist uploaded
raw logs by default.

Current `pyproject.toml` declares no FastAPI or ASGI dependencies. A future
adapter will need an explicit local dependency decision (FastAPI, an ASGI
server such as Uvicorn, and multipart parsing support if using file uploads).
Those packages must be available locally for installation; runtime use should
not fetch packages or call external services.

## 5. Long-running local inference and UI behavior

CPU inference can take over 100 seconds. A live `phi4-mini:latest` run in
this environment took about 107 seconds for a multi-stage explanation, and a
cold request exceeded the 90-second default and fell back. Therefore:

1. Upload and analyze first; render the deterministic findings/incidents as
   soon as `POST /api/v1/analyze` returns.
2. Show severity, score breakdown, timeline, supporting event links, coverage,
   missing evidence, limitations, and deterministic next steps immediately.
3. Start explanation work only on explicit user action or a clear UI option.
4. Display queued/running state without blocking the report. Poll the proposed
   job endpoint every few seconds; allow navigation and cancellation of the
   browser wait without implying that the server-side model call was stopped.
5. Attach a returned explanation to its incident by `incident_id`, visibly
   labeled `AI-generated explanation — not evidence`. Display its status and
   fallback/rejection reason. Keep AI suggested actions separate from
   `recommended_next_steps`.
6. Never replace, sort by, or restyle away the deterministic severity/score
   based on AI prose. A rejected or unavailable response must leave the
   deterministic analysis usable.

The current CLI is synchronous when `--explain` is used; the asynchronous job
behavior above is a frontend/API recommendation, not an existing feature.

## 6. Offline serving requirements

- Serve compiled/static vanilla HTML, CSS, and JavaScript from the local
  FastAPI process or a bundled local static server. Use same-origin relative
  URLs such as `/api/v1/analyze`.
- Bind to loopback (`127.0.0.1`) for a single-user desktop app. Do not expose
  the development server on the LAN unless a later security design explicitly
  requires it.
- Do not use CDNs, remote fonts, analytics, telemetry, cloud APIs, external
  scripts, external images, or runtime package/model downloads.
- Vendor or locally install frontend/backend dependencies before the offline
  demo. The current Python analysis core itself uses only the standard
  library; Ollama must already be installed locally with `phi4-mini:latest`.
- Keep Ollama requests in the Python backend and loopback-only. The browser
  should call only the local TRACE-Verified origin, not Ollama directly.
- Prefer a same-origin app so no permissive CORS policy is needed. The UI must
  present uploaded log values as untrusted text, not HTML; escape them before
  rendering.

## 7. Current backend run instructions (Windows PowerShell)

From the repository root, create/activate the documented environment and
install the package:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

The equivalent install without tests is `python -m pip install -e .`. Then
run the current backend:

```powershell
trace-verified ingest .\tests\fixtures\windows_timecreated.jsonl --output .\ingestion.json
trace-verified detect .\tests\fixtures\windows_timecreated.jsonl --output .\findings.json
trace-verified analyze .\tests\fixtures\windows_privilege_events.jsonl --output .\analysis.json
trace-verified analyze .\tests\fixtures\windows_timecreated.jsonl .\tests\fixtures\windows_privilege_events.jsonl --output .\multi-file-analysis.json
```

For optional local explanations, start Ollama separately, confirm the local
model is present, and opt in:

```powershell
ollama list
python scripts/check_ollama.py --model phi4-mini:latest
trace-verified analyze .\path\to\events.jsonl --explain --max-explain 3 --explain-timeout 180 --output .\analysis-with-explanations.json
```

The configured CLI default is 180 seconds for a slow CPU cold start. No model
is downloaded by TRACE-Verified.

## 8. Frontend authority constraints

The frontend may filter, search, sort for display, and format the values
returned by the backend. It must not:

- parse logs or re-run any detector rules in JavaScript;
- merge findings/incidents or infer entities from IP-only matches;
- calculate, adjust, or relabel deterministic score or severity;
- infer successful authentication, privilege escalation, lateral movement,
  or defense evasion without backend evidence;
- create, suppress, or edit finding IDs, incident IDs, event IDs, evidence,
  coverage, correlation rationale, or deterministic recommendations;
- treat a missing field, skipped detector, malformed row, warning, or
  unavailable explanation as an all-clear;
- let AI text alter incident data, deterministic actions, or evidence
  references.

Display values from the backend, link timelines/findings by their IDs, and
keep AI interpretation in its separate `ai_explanations` field. Severity and
scoring remain deterministic Python decisions.
