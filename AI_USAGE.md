# Local AI usage

TRACE-Verified can optionally ask the local Ollama model `phi4-mini:latest` at
`http://localhost:11434` to explain a deterministic incident. The feature is
opt-in through `trace-verified analyze INPUT --explain`. The base analyze
workflow does not call Ollama.

## Authority boundaries

- Python ingestion, detection, event evidence, correlation, severity, score,
  score breakdown, and deterministic next steps are authoritative.
- The model receives only a bounded, incident-scoped evidence dossier. Raw
  event values and log-derived narrative fields are explicitly marked as
  untrusted data. Complete raw records are not sent.
- Model output must be JSON with the documented explanation fields. The adapter
  checks types, cited event IDs, entity and count claims, supported outcomes,
  deterministic severity/score claims, and explicit chronology statements.
  Invalid output is retried once with rejection feedback, then rejected in
  favor of a deterministic fallback.
- AI text is labeled `AI-generated explanation — not evidence`. It is an
  interpretation, not a verified fact. Suggested model actions
  remain separate from deterministic recommendations.
- Neither log content nor model output is executed. The model cannot add
  findings or change deterministic incident fields.
- Verification uses bounded checks over text; it cannot prove every free-form
  statement true or detect every subtle contradiction. Review cited evidence
  before acting on AI-generated conclusions.

## Offline behavior

The adapter accepts only HTTP loopback endpoints, disables proxy use and
redirects, uses request timeouts, and bounds response size. It does not download
models. `phi4-mini:latest` must already be available to the local Ollama
installation. If Ollama is unavailable or output fails verification,
`--explain` still returns the deterministic analysis with an explicit status.

No cloud inference, analytics, telemetry, or runtime internet request is used.
The only runtime network connection is the explicitly enabled request to the
configured localhost Ollama endpoint. Synthetic checks do not establish
real-world detection or explanation accuracy.
