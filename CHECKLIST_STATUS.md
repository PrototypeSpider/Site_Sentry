# SiteSentry backend checklist status

Legend: **Done** = implemented and covered or inspected; **Partial** = useful implementation exists but a stated requirement is not met; **Pending** = needs external tool/data/deployment credentials or work not yet implemented. These statuses describe code state, not UI checklist controls.

**Current count: 71 done, 4 pending (75 total, counting the two cross-cutting criteria below).**

- [x] Cross-cutting: a failed scan is never a passed check.
- [x] Cross-cutting: model output is advisory and is not vulnerability evidence.

## A. Backend foundation

- [x] Python environment instructions and requirements file (the venv itself is local and ignored, not committed).
- [x] Flask API and environment-backed configuration.
- [x] Common finding/evidence schema.
- [x] Scan IDs, timestamps, queued/running/completed/error/cancelled states.
- [x] Structured logging and generic exception handling.
- [x] Pytest suite and settings validation.

## B. Scope and safety

- [x] Domain allowlist and authorization reference in scoped mode; reference is auditable metadata, not independent proof of consent.
- [x] URL scheme, hostname, credentials, and standard-port validation.
- [x] Reject non-public IP destinations.
- [x] Pin sockets to validated IPs while preserving TLS SNI and host verification.
- [x] Revalidate every redirect and enforce domain scope.
- [x] Connect/read limits, 1 MB response cap, bounded queue and worker count.
- [ ] Shared rate limiting and authentication are implemented with Redis Lua, Redis queue, static bearer token or trusted proxy identity; an isolated two-instance verification harness is available at `integrations/verify_redis_multi_instance.py`, but the Redis service is not running here, so live multi-instance verification remains pending.
- [x] External tools run through bounded fixed-argument adapters; deployment still needs OS/container isolation for strong least-privilege.
- [x] Client cannot supply a command, executable path, or tool flags; no shell runner exists.

## C. Core scanner

- [x] HTTPS reachability result.
- [x] Standard TLS chain and hostname verification.
- [x] Certificate not-before/not-after and expiry checks.
- [x] Negotiated TLS version and cipher evidence.
- [x] Security headers and selected directive checks.
- [x] HTTP-to-HTTPS redirect behavior for the submitted URL.
- [x] Status, redirect chain, content type and response bytes.
- [x] Bounded DNS A/AAAA/CNAME/NS/TXT observations.
- [x] Separate DNS, TLS, connection, read, HTTP and redirect policy errors.
- [x] Finding timestamps, source, rule version and limitations.

## D. Kali / external tool integrations

- [x] Individual adapters and fixed parsers for OpenSSL, testssl.sh, WhatWeb, wafw00f, Nmap, Nikto, Nuclei, SSlyze and ZAP.
- [x] Python `ssl` implementation supplies baseline certificate and handshake evidence.
- [x] testssl.sh deeper TLS scan adapter (binary unavailable for live run).
- [x] WhatWeb technology fingerprinting adapter (binary unavailable for live run).
- [x] wafw00f WAF indicator adapter (binary unavailable for live run).
- [x] Nmap adapter with separate explicit network-scope authorization gate (binary unavailable for live run).
- [x] Nikto adapter (binary unavailable for live run).
- [x] Nuclei adapter requires an explicit curated template directory and rejects exploit/intrusive-marked templates (binary unavailable for live run).
- [x] Tool-specific machine-readable parsers, timeout/output policies, and normalized/deduplicated observations.

## E. Rule and risk engine

- [x] Stable IDs and rule version.
- [x] TLS and header rules.
- [x] HSTS max-age, nosniff, referrer token, and framing directive/value checks.
- [x] Severity field independent of optional ML confidence.
- [x] Rule evidence and remediation guidance.
- [x] Documented review heuristics and header absence limitations.
- [x] Conflicting multi-tool result reconciliation preserves conflicting observations as inconclusive.
- [x] Unsupported/failed checks remain errors or not-assessed, not pass.
- [x] Rule regression tests.

## F. ML and DL

- [x] Defined target: advisory configuration-review label, not exploitability.
- [x] Dataset collection schema, reviewer rubric, uncertain-label policy, and domain-held-out evaluation protocol documented; actual labeled observations still required for training.
- [x] Versioned numeric/header feature schema.
- [x] Group holdout by target group, with overlap checks.
- [x] Deterministic rule findings remain the baseline; ML never changes them.
- [x] Logistic Regression train/evaluate pipeline.
- [x] Per-class precision/recall/F1, macro-F1, confusion matrix, and false-positive rate; configuration-review training now reports both ML and deterministic SiteSentry rule-baseline metrics.
- [x] Sigmoid probability calibration fitted on training data only.
- [x] Model, feature, dataset hash and evaluation metadata.
- [x] Predictions advisory; no model artifact is deployed by default.
- [ ] Real model training/evaluation for the defined configuration-review target; the supplied MSWD data has a different malicious-site classification target and cannot validate this model.
- [x] DL baseline-comparison helper evaluates both models on the same domain-group split and reports metric deltas; meaningful improvement claims still require real labeled data.

## G. XAI and LLM

- [x] Direct rule-trigger explanation.
- [x] SHAP integration for the supported calibrated Logistic Regression pipeline; unavailable when no compatible trained model is loaded.
- [x] Model feature contributions and version when a trained calibrated baseline is loaded.
- [x] Gemini/Grok provider interface.
- [x] LLM receives only normalized finding evidence, not fetched page content; response schema validated.
- [x] Prompt injection guidance and bounded/redacted payload.
- [x] API timeout/retry on Grok and Gemini, response limits, and deterministic fallback.
- [x] Deterministic scan findings retained when AI is unavailable.
- [ ] Provider live-call verification (CLI reads `.env` and redacts SDK errors; actual call requires a rotated credential and supported model name).

## H. Reports, persistence and tests

- [x] SQLite scan records and audit events.
- [x] SQLite `user_version` migration baseline.
- [x] Canonical JSON report.
- [x] PDF generated from stored normalized JSON result.
- [x] Scan history and SHA-256 report integrity metadata.
- [x] Invalid URL, SSRF, scope, failed target, API, header, redaction, redirect and ML input regression tests.
- [x] Deterministic tool parser/timeout fixtures, typed network error tests, and AI schema/redaction/fallback tests.
- [ ] Held-out real ML evaluation for configuration-review labels; the supplied MSWD set was evaluated separately for malicious-site classification.
- [x] Deployment, scope and limitation documentation.

## Dataset needed to finish configuration-review ML/DL items

The supplied MSWD dataset is a separate malicious-site classification task. Its advisory Logistic Regression, Random Forest, and MLP models were trained and evaluated with a hostname-grouped holdout; results and limitations are in `models/mswd-final/mswd_training_report.json`. This does not satisfy configuration-review model validation.

Provide a labeled CSV with these columns:

```text
target_group,label,https,tls_verified,tls_days_remaining,headers_json
```

Include at least 20 reviewed rows and enough independent `target_group` values for both classes to appear in training and held-out groups. `label` should be a documented configuration-review class such as `compliant` / `review`; it must not claim that a vulnerability is exploitable. Include collection date/source and labeling rationale in a companion provenance file. The trainer records a content hash and keeps target groups disjoint across train and test. Synthetic rows are suitable only for exercising code, not model-performance claims.
