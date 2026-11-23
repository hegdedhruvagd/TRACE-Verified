# TRACE-Verified

Offline-first cybersecurity event analysis for Windows. TRACE-Verified
provides deterministic CSV/JSON/JSONL ingestion, detection, incident
correlation and heuristic severity scoring. Optional incident explanations
use a local Ollama model; deterministic Python remains authoritative. Runtime
network requests are limited to the configured localhost Ollama endpoint when
`--explain` is explicitly enabled.

## Requirements

- Python 3.11 or later
- Optional for tests: pytest 9.2.0
- Optional for local explanations: Ollama running on this computer

## Setup

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
```

The application core uses only the Python standard library. To install without
test tools, use `python -m pip install -e .`.

## Ingest a file

```powershell
trace-verified ingest .\path\to\events.csv --output .\report.json
python -m trace_verified.cli ingest .\path\to\events.jsonl
```

Supported inputs are CSV, JSON arrays/objects, and JSON Lines (`.jsonl` or
`.ndjson`). The ingestion report includes malformed-row accounting, field
coverage, timestamp warnings, and normalized events. Original values remain
available in each event's `raw_record`. Naive timestamps are retained with an
explicit warning; no timezone is assumed. User and host matching is
case-insensitive after conservative normalization. IP addresses are not used
to merge entities.

## Generate deterministic synthetic data

```powershell
python -m trace_verified.corpus --output .\synthetic.jsonl --count 100 --seed 7
```

This creates illustrative synthetic records, not a benchmark or a claim about
detection quality.

## Run deterministic detections

```powershell
trace-verified detect .\path\to\events.jsonl --output .\findings.json
trace-verified detect .\path\to\events.csv --auth-window-minutes 15 --brute-force-threshold 6
trace-verified analyze .\path\to\events.jsonl --correlation-window-minutes 30 --output .\incidents.json
python -m trace_verified.evaluate
```

The first deterministic detector milestone covers repeated authentication
failures and password spraying, success after repeated failures with matching
account/source context, explicit privilege/group change audit events, and
suspicious process patterns. Reports include supporting event IDs, evidence,
limitations, severity contribution, and whether each detector ran or was
skipped. A privilege event proves a recorded change, not whether it was
authorized; configure an expected actor allowlist when that policy is known.
Encoded PowerShell is decoded as text only, with size limits; commands are never
executed. Synthetic evaluation is a deliberately small scenario check and does
not establish detection accuracy in real logs.

## Correlate and score incidents

```powershell
trace-verified analyze .\path\to\events.jsonl --correlation-window-minutes 30 --max-incident-findings 100
trace-verified analyze .\path\to\auth.csv .\path\to\endpoint.jsonl --correlation-window-minutes 30 --max-incident-duration-minutes 240
trace-verified analyze .\path\to\events.jsonl --approved-finding-id fnd_0123456789abcdef01234567
python -m trace_verified.incident_evaluate --findings 100000
```

Correlation uses normalized user+host or user+source-IP keys, a configurable
maximum gap, maximum incident duration, and maximum finding count. Multiple
CSV, JSON, and JSONL files can be analyzed together; per-file ingestion
coverage and provenance are retained. IP-only matches never create an
incident. Scores are transparent additive heuristics from detector severity,
confirmed authentication success, distinct attack stages, and host spread.
Evidence is credited once, and each rule's score contribution is capped at its
strongest configured severity. Thresholds are Low 0–24, Medium 25–49, High
50–74, and Critical 75–100. Scores are investigation priorities, not validated
risk probabilities. Approved finding IDs are excluded from incident scoring
and stage interpretation while remaining visible in the report.

## Optional local AI explanations

```powershell
trace-verified analyze .\path\to\events.jsonl --explain
python -m trace_verified.cli analyze .\path\to\events.jsonl --explain --output .\incidents-with-explanations.json
trace-verified analyze .\path\to\events.jsonl --explain --max-explain 3 --explain-timeout 180
python scripts/check_ollama.py --model phi4-mini:latest
```

Explanations use the already-installed local Ollama model `phi4-mini:latest` at
`http://localhost:11434`. Start Ollama locally and confirm the model is present
with `ollama list` before using `--explain`. TRACE-Verified does not download a
model. Its Ollama requests use only loopback, disable proxy use and redirects,
and have bounded time and response sizes.

Without `--explain`, `analyze` behaves as before and makes no Ollama request.
With the flag, each incident gets a separate `ai_explanations` entry with a
status of `local_model`, `deterministic_fallback`, or
`rejected_by_verification`. By default, only the three highest-scored
incidents are sent to the model; other incidents receive fallback entries.
`--max-explain` changes that cap and `--explain-timeout` sets the request
timeout. If Ollama is stopped, times out, or returns unverifiable output,
analysis still completes with a deterministic fallback. A transport failure
stops further model requests in the same run.

Deterministic findings, event evidence, incident severity, score, score
breakdown, and recommended next steps remain authoritative and unchanged. The
AI-generated explanation is labeled as interpretation, not evidence. The
model receives a compact incident-scoped dossier; raw log fields and other
log-derived text are marked untrusted and bounded. Its structured response is
checked for schema, required dossier event citations, entity/count claims,
unsupported outcomes, deterministic severity and score claims, and explicit
chronology conflicts. Invalid output is retried once with rejection feedback;
then it is rejected and replaced with deterministic text. Neither logs nor
model output are executed.

These checks are bounded rule-based safeguards, not a proof that every
natural-language statement is true. Treat AI text as untrusted interpretation
and verify consequential conclusions against the cited deterministic
evidence. Synthetic tests establish software behavior, not real-world
detection accuracy.

The standalone checker is also available:

```powershell
python scripts/check_ollama.py
```

It only checks a loopback Ollama service and its local model list, and never
downloads a model. Ingestion and deterministic analysis do not depend on
Ollama being ready.

## Project structure

```text
trace_verified/       schemas, ingestion, detection, correlation, CLI, explainer
scripts/              local Ollama health/model checker
tests/fixtures/       small CSV and JSON/JSONL input examples
tests/                unit and synthetic evaluation tests
AI_USAGE.md            local inference policy and model boundaries
```

Deterministic Python remains responsible for parsing, detection, correlation,
counts, severity, confidence, and remediation. Optional local Phi explanations
only describe supplied evidence and suggest investigation steps; structured
output is verified and kept separate from deterministic incident fields.
There are no cloud calls or runtime internet requests.
