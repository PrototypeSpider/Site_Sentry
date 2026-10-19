# SiteSentry: Project Architecture, Algorithms, and Operating Guide

**Document type:** Technical project guide  
**Audience:** Project owner, developers, reviewers, and operators  
**Project:** SiteSentry passive website security assessment prototype  
**Guide version:** 1.0  
**Last checked against source:** 2026-10-19

> This guide describes the implementation in this repository. A check marked `pass` means that one specific observation passed one specific rule. It does not certify a site as secure. A failed or incomplete scan is not a pass.

## How to use this guide

1. Read Sections 1–5 first to understand the architecture and the full scan path.
2. Use Section 6 to learn what Quick, Standard, and Advanced run.
3. Read Sections 7–9 for the deterministic rules, risk score, and tool-inspired detection logic.
4. Read Sections 10–12 for ML, SHAP/XAI, and optional LLM explanations. These are separate from authoritative scanner findings.
5. Use Sections 13–16 to run the project, configure it, interpret failures, and maintain the implementation.
6. When explaining a result to someone else, state the scan profile, scan state, checks that ran, evidence, limitations, and whether a model output is advisory.

The primary implementation files are linked inline. When a workflow changes, update the matching section here and update the short setup/API overview in `README.md`.

## 1. What SiteSentry does

SiteSentry accepts a public HTTP(S) URL, safely collects a bounded set of DNS, HTTP, and TLS observations, and evaluates those observations with deterministic rules. The backend stores a normalized scan record and makes it available to the Streamlit dashboard and report endpoints.

Its main output is a list of **findings**. Each finding contains a stable check ID, human-readable name, status, severity, evidence, explanation, recommendation, observation time, rule version, and source. Additional fields may contain risk prioritization, standards guidance, a model assessment, SHAP information, or an optional AI explanation.

SiteSentry is a passive configuration assessment. It does not prove exploitability, crawl an application, authenticate to a site, test business logic, execute payloads, or perform a port scan. The advanced fingerprint checks described below reuse the already-collected response and handshake; they do not call the named external programs.

## 2. System architecture

```text
Operator
  │
  ├── Streamlit dashboard (dashboard/app.py)
  │       └── authenticated HTTP requests (dashboard/scanner.py)
  │
  └──────────────────────────────► Flask API (app.py)
                                      ├── Authentication, input and scope checks
                                      ├── Rate limits, quotas and bounded scan queue
                                      ├── Scanner worker (scanner/engine.py)
                                      │     ├── URL/DNS/IP safety (scanner/url_validation.py)
                                      │     ├── Pinned HTTP/TLS transport (scanner/transport.py)
                                      │     ├── DNS observations (scanner/dns_checks.py)
                                      │     ├── Deterministic rules (scanner/checks.py)
                                      │     ├── Advanced passive fingerprints
                                      │     ├── Optional configuration-review model + SHAP
                                      │     └── Optional Gemini/Grok explanation
                                      ├── SQLite history and audit events (storage.py)
                                      └── JSON/PDF/XAI reports

Separate model workbench:
  Streamlit/API ──► packaged MSWD classifier ──► prediction + SHAP
                      (does not control scan findings)
```

### Main folders

| Path | Responsibility |
| --- | --- |
| `app.py`, `config.py`, `rate_limit.py` | Flask API, environment configuration, authentication, quotas, queue, and API routes |
| `scanner/` | Safe collection, observations, findings, profile logic, rules, risk annotations, and passive fingerprints |
| `dashboard/` | Streamlit UI and its server-side authenticated API client |
| `storage.py`, `reports/` | SQLite persistence, scan history, workflow state, and report serialization |
| `ml/` | Feature extraction, model training, inference, deployment bundles, and labeling guidance |
| `models/` | Trained classifier artifacts, integrity manifests, and training report |
| `xai/` | SHAP feature attribution and human-readable scan report generation |
| `integrations/` | Optional provider, Redis verification, and CI helper integrations |
| `scanner/tool_adapters/` | Opt-in adapters/parsers for separately installed security utilities; not run automatically by normal scans |
| `tests/` | Backend, dashboard client, rate-limit, and adapter checks |
| `data/`, `reports/` | Local scan database, input datasets, and exported reports; contents depend on local setup |

## 3. Full scan lifecycle

1. **The operator submits a URL and profile.** The dashboard normalizes a user-entered URL for convenience and sends `{ "url": "...", "profile": "quick|standard|advanced" }` to `POST /api/scans`. The dashboard never performs the target scan itself.
2. **The API authenticates the request.** The default deployment uses a bearer token. A trusted reverse-proxy identity mode is also supported. The browser does not receive the server-side API token.
3. **The backend validates the target.** It accepts HTTP or HTTPS on standard ports, rejects embedded credentials and query strings, validates hostnames and address scope, and checks the optional approved-domain allowlist. Loopback, private, link-local, reserved, and prohibited destinations are rejected.
4. **The backend applies capacity controls.** It enforces per-client and global rate/quota limits and a bounded pending queue. In single-instance mode these controls are local to the process. Multi-instance mode requires Redis for shared queue and limit coordination.
5. **The API creates a scan ID and queues work.** The initial response is HTTP 202 with a scan ID and `queued` state. A worker later changes the state to `running`, then `completed`, `partial`, or `error`.
6. **The scanner collects DNS as selected by the profile.** It requests bounded A, AAAA, CNAME, NS, and TXT observations with resolver timeouts. DNS errors are recorded separately; a failed DNS record lookup is not treated as an HTTP/TLS pass.
7. **The transport collects one bounded web response.** Each destination is DNS-validated, pinned to a validated public IP for the connection, and contacted with the original hostname for HTTP Host/SNI and TLS hostname verification. Redirects are followed manually and revalidated one by one. Response size, redirect count, and connect/read times are bounded.
8. **The engine evaluates the selected checks.** It converts observed data into deterministic findings. Advanced adds extra negotiated TLS/CSP checks and passive fingerprints.
9. **Optional inference/explanation runs separately.** If a configuration-review artifact exists, the engine attaches its advisory classification and SHAP attribution. If a Gemini/Grok provider is configured, it may generate a structured explanation. Neither can change deterministic status or severity.
10. **The result is normalized and stored.** Findings receive risk and limited standards annotations; canonical JSON is persisted with scan metadata. SQLite also records status history and audit events.
11. **The dashboard refreshes the result.** It polls the scan state, displays metrics and findings, shows scan history and per-profile activity, and can request a human-readable XAI report or JSON/PDF report.

### Scan status versus finding status

The scan-level state describes whether collection completed: `queued`, `running`, `completed`, `partial`, `error`, or `cancelled`. Finding-level status describes one check: `pass`, `finding`, `warning`, `fail`, `error`, `not_assessed`, or `inconclusive`.

If collection fails, SiteSentry records a scan-level error and does not mark uncollected checks as passed. For example, a redirect URL containing a query string is rejected by policy to avoid exposing URL-carried secrets. That is a scan failure, not evidence that the target passed or failed the security checks.

## 4. API and dashboard responsibilities

### Backend API

The Flask API is authoritative for authentication, scope validation, scan submission, scan status/history, findings, report generation, model inference, and workflow updates. Important routes include:

| Route | Purpose |
| --- | --- |
| `GET /api/health` | Backend and queue activity status |
| `POST /api/scans` | Validate, authorize, and enqueue a scan |
| `GET /api/scans` | List scan history for the authenticated identity |
| `GET /api/scans/<scan_id>` | Read scan status and summary |
| `GET /api/scans/<scan_id>/findings` | Read normalized findings |
| `GET /api/scans/<scan_id>/report?format=json|pdf` | Export canonical scan result |
| `GET /api/scans/<scan_id>/xai-report` | Generate a plain-language explanation from normalized findings |
| `GET /api/models` | List checksum-verified deployed model bundles |
| `POST /api/models/<model_id>/predict` | Request a separate advisory prediction and SHAP explanation |
| `GET/PUT .../workflow` | Read/update owner-scoped finding workflow status |

### Streamlit dashboard

The dashboard is a server-side client. It offers Quick/Standard/Advanced selection, URL submission, scan history, status polling, finding tables, metrics, Sankey visualization, and an XAI report button. Its health/activity panel refreshes every ten seconds and groups scan logs by profile. The API token is read by the Streamlit server and sent only to the backend.

The dashboard translates raw statuses to display labels: `pass` becomes Pass; `fail`/`error` become Fail; other statuses appear as Warn. Read the raw finding status and evidence when exact technical meaning matters.

## 5. Safe target and collection logic

The scope and transport controls are part of the scanner’s algorithm, not optional UI checks:

- Only `http` and `https` schemes and standard ports are accepted.
- URL credentials and query parameters are rejected. URL paths may still be scanned subject to target validation, but report URLs are sanitized.
- A configured `SITESENTRY_ALLOWED_DOMAINS` allowlist restricts hostname scope. An empty list means any otherwise-valid public hostname is eligible, subject to API authentication and network restrictions.
- Private, loopback, link-local, reserved, and non-global IP addresses are blocked.
- DNS results are validated and the socket connects to a pinned public address; TLS still checks the original hostname.
- Every redirect destination is validated again for scheme, address, port, and configured scope.
- Redirects, response body bytes, connection time, read time, pending jobs, and workers are bounded.
- The transport reads the response body only to a byte limit and records byte count/truncation. It does not parse page HTML or crawl links.
- Client requests cannot provide an executable path, shell command, or arbitrary tool flags.

## 6. Scan profiles and check coverage

| Profile | Runs | Skips/adds |
| --- | --- | --- |
| **Quick** | HTTPS reachability, TLS certificate validation/expiry, HSTS, CSP presence/quality baseline, X-Content-Type-Options, clickjacking protection | Skips DNS and filters out other baseline findings to keep the quick profile short |
| **Standard** | DNS observations plus the full baseline HTTP/TLS/header checks: reachability, certificate validation/expiry, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, clickjacking protection, visible cookie attributes, and redirect behavior when a redirect was observed | No advanced negotiated-TLS/CSP/fingerprint checks |
| **Advanced** | Standard coverage plus negotiated TLS protocol and cipher review; deeper CSP script-source directive review; HTTP technology/service banner fingerprints; heuristic WAF header indicators; curated evidence-only passive web templates | Still does not crawl, probe ports, issue test payloads, invoke Nmap/Nikto/Nuclei/etc., or enumerate all TLS configurations |

DNS is stored as bounded observations in result metadata (`metadata.dns`); it is not a claim that DNS configuration is fully secure. Quick profile explicitly records DNS as skipped by profile.

## 7. Deterministic rules and finding semantics

Deterministic checks are the authoritative assessment logic. They evaluate the collected response without a trained classifier.

### Main checks

- **HTTPS reachability:** whether the final response URL used HTTPS, with the observed HTTP status.
- **TLS certificate validation:** whether the platform TLS stack verified the chain and hostname during this connection.
- **TLS certificate expiry:** parses the observed certificate `notAfter`; expired is `fail`, expiring within 30 days is `warning`, otherwise `pass`.
- **HSTS:** inspects header presence and `max-age`; flags invalid/missing values and warns below the one-year review threshold. It reports `includeSubDomains` and `preload` as context, not a blanket instruction to enable them.
- **CSP:** checks policy presence and selected directive quality. It reviews broad wildcards, missing `default-src`, `unsafe-eval`, and `unsafe-inline` without nonce/hash support.
- **X-Content-Type-Options:** recognizes `nosniff` as the expected value.
- **Referrer-Policy:** checks whether the value is one of the recognized policy tokens.
- **Permissions-Policy:** reports whether a policy header was observed; whether a policy is needed depends on browser features used by the site.
- **Clickjacking protection:** looks for CSP `frame-ancestors` or effective `X-Frame-Options` values (`DENY`/`SAMEORIGIN`).
- **Cookie attributes:** counts missing Secure/HttpOnly/SameSite attributes for visible `Set-Cookie` values, but never outputs cookie names or values. The response is not a complete cookie inventory and application context matters.
- **HTTP-to-HTTPS redirect:** when a redirect chain was observed, compares initial and final schemes. It assesses only the requested path/redirect sequence.
- **Redirect handling:** reports that every observed redirect was revalidated and safely followed.
- **Advanced TLS:** reports the protocol and cipher negotiated on one connection. It identifies selected legacy protocol/cipher names; it is not a full supported-protocol or cipher-suite enumeration.
- **Advanced CSP directives:** evaluates selected script-source directives, not every browser policy semantic or application flow.

### Status and severity

- `pass`: the measured condition matched the local rule.
- `finding`: a measured configuration issue matched the rule.
- `warning`: evidence merits review but does not establish exploitability.
- `fail`: the check measured a condition defined as failed, such as expired certificate or outdated negotiated protocol.
- `error`: the individual check could not complete or evidence extraction failed.
- `not_assessed`: the condition did not apply or the profile did not collect the necessary evidence.
- `inconclusive`: available evidence cannot establish a reliable pass/fail result.

Severity (`critical`, `high`, `medium`, `low`, `informational`) describes the rule’s review priority. It is separate from status and model confidence. A missing optional header is configuration evidence, not proof of an exploitable vulnerability.

## 8. Risk prioritization and standards mappings

`scanner/risk.py` adds an advisory score to each finding. It uses a severity weight, evidence-confidence factor, exposure factor, and check-specific impact factor. Direct evidence on a pass/finding/warning/fail produces a higher confidence factor than incomplete or absent evidence. Scores are bounded at 100.

The overall score sums the maximum finding score within each check family (for example, header or TLS), then caps the result at 100. This reduces double-counting related checks. The score is a prioritization aid only; it is not a probability, a CVSS score, or a claim of exploitability. Standards mappings are narrow references with applicability notes and do not certify conformance to OWASP ASVS or another full standard.

## 9. Security-tool-inspired logic in Advanced

The project contains optional command adapters for some external programs, but normal dashboard scans do **not** invoke those programs. Advanced profile uses local Python logic over the already-collected response/handshake:

| Inspiration | SiteSentry’s in-process logic | Important boundary |
| --- | --- | --- |
| testssl.sh-style TLS review | Reviews the negotiated TLS version and cipher; flags a bounded list of legacy values | One negotiated handshake only; no cipher/protocol enumeration |
| WhatWeb-style fingerprinting | Reads selected HTTP banner headers such as Server, X-Powered-By, X-Generator, and Via | Heuristic product hints; may be hidden or spoofed; no page signature crawl |
| Nmap-style service identification | Summarizes HTTP vs HTTPS, observed TLS version, and an exposed server banner from the connection already made | No port discovery or network scan |
| wafw00f-style WAF detection | Checks a short set of common vendor/header indicators | Presence is not proof of effective protection; absence does not prove no WAF |
| Nikto-style configuration review | Checks selected observed banner disclosure, unusual header values, and HTTP 5xx response | Does not request known paths or enumerate server files |
| Nuclei-style templates | Applies a small curated set of evidence-only conditions to captured headers/status | No payload templates or extra HTTP requests; findings remain passive review hints |

These detections are under `scanner/passive_fingerprints.py`; advanced TLS/CSP rules are in `scanner/checks.py`. A fingerprint can be `inconclusive` even when an indicator was found because identification is not vulnerability confirmation. The exact external tools are available only through separate opt-in adapters with their own gates and are not selected by the standard scan API.

## 10. Machine-learning models and their roles

SiteSentry has two distinct ML tasks. They must not be mixed together.

### A. Supplied MSWD malicious-site classification

The supplied MSWD CSV/ZIP trains three packaged classifiers in `ml/train_mswd.py`:

| Model | Project-specific role |
| --- | --- |
| Calibrated Logistic Regression | Baseline classifier for MSWD records; sigmoid calibration is applied to its probabilities |
| Random Forest (RF) | 400-tree ensemble comparison on the same MSWD feature table; class balancing is enabled |
| MLP | Two-hidden-layer neural network (`64, 32`) comparison; numeric features are scaled, early stopping and regularization are used |

**This task predicts the dataset’s benign/malicious class. It does not decide whether a live target passes SiteSentry checks.** These models are packaged under `models/mswd-final/` and can be called through the authenticated model API or dashboard’s advisory model workbench. XGBoost is not trained or packaged in the current project.

Training pipeline details:

1. Read the semicolon-delimited CSV and check that the ZIP’s CSV matches the standalone CSV.
2. Keep rows with class values `0` or `1`; report excluded unlabeled rows.
3. Derive a normalized hostname group for each row and split with `GroupShuffleSplit`, keeping hostnames out of both partitions at once.
4. Exclude raw domain, IP, hash, class, VirusTotal, and Safe Browsing columns from predictors to reduce leakage.
5. Convert numeric values; treat blank and selected `-1` values as missing. Impute numeric values with the median and categorical values with the most frequent value; one-hot encode categories.
6. Train Logistic Regression, Random Forest, and MLP on the same training partition; calculate accuracy, macro-F1, ROC-AUC, Brier score, per-class precision/recall/F1, confusion matrix, and malicious false-positive/false-negative rates on the held-out partition.
7. Save each complete sklearn preprocessing/model pipeline, feature schema, selected SHAP background rows, dataset digest, metrics, limitations, and a SHA-256 manifest.

The supplied data’s numeric class mapping is inferred as `0=benign`, `1=malicious`; the CSV/ZIP does not explicitly document that mapping. Treat this as an assumption until confirmed by dataset authors. Dataset predictions are advisory and do not establish exploitability.

### B. Configuration-review model

`ml/train.py` supports a separate calibrated Logistic Regression model for `compliant` vs `review`. It requires a real, reviewed CSV with provenance and a documented label rubric. It creates compact features from HTTPS, TLS verification/expiry, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, and frame-protection observations.

The split groups observations by `target_group`; the trainer also compares the model with a deterministic rule baseline on the same held-out records. The artifact is saved as `models/config_review.joblib`. If it is absent or incompatible, live scans report model status as not configured/incompatible and deterministic findings still work. The current repository does not contain a reviewed configuration-review dataset, so do not claim that this model was trained or evaluated on qualified human labels unless that dataset and report exist.

In a scan, if this artifact is available, the engine predicts an advisory configuration-review label from the response features and attaches it to findings. It does not change any finding status, severity, or remediation.

## 11. SHAP/XAI and human-readable explanations

### SHAP for model behavior

`xai/feature_attribution.py` explains the selected model output with permutation SHAP. It uses saved training-reference/background rows, asks what changes the model’s positive-class probability relative to those rows, and returns feature contributions ordered by absolute magnitude. For MSWD, the explained class is malicious; for the configuration-review bundle, it is review.

Read a positive contribution as “this feature moved this model output upward relative to its reference,” and a negative contribution as “it moved the output downward.” SHAP is a description of model behavior, not causation or independent security evidence. SHAP can return unsupported/unavailable states; this should not prevent a scan or model prediction from being returned.

### XAI report button

The dashboard’s **Generate XAI report** button requests `/api/scans/<scan_id>/xai-report`. The report generator uses the normalized result’s profile, scan state, metrics, findings, evidence, rule explanations, recommendations, risk rationale, standards notes, limitations, and any available SHAP contributions. It rephrases evidence for readability and hides URL paths/query values. This report is generated from recorded scan evidence; it does not require Gemini/Grok.

### Optional Gemini/Grok explanations

An optional provider can explain normalized finding evidence in a structured response. The provider receives bounded/redacted evidence, not arbitrary page HTML. The response must match the required schema. Timeouts, retry bounds, validation, and deterministic fallback are used. AI output cannot invent or override a finding’s deterministic status or severity, and the scan remains available if a provider is unavailable.

## 12. Persistence, reports, and remediation workflow

- SQLite schema version is maintained in `storage.py`. It stores scan metadata, status, profile, owner, normalized result JSON, audit events, and finding workflow state.
- A scan result has a schema version, scan ID, target, state, timestamps, scanner version, executed modules, summary, metrics, findings, risk summary, errors, limitations, and collection metadata.
- JSON is the canonical report representation. PDF is generated from the same normalized result, avoiding a separate assessment path.
- Workflow states allow `acknowledged` or `fixed`; reopening removes the saved workflow state. A “fixed” workflow label is only validated by a follow-up rescan of the same host/port/path that passes the corresponding check.
- Scan comparison is constrained to the same target host/port/path and identifies new, resolved, recurring, changed, and unchanged checks.
- Model artifacts use joblib, so load them only from trusted sources. The API checks a sidecar SHA-256 manifest before listing or using a bundle.

## 13. Start and use the project

Run these commands in PowerShell from the repository root (`J:\SiteSentry`). The backend and dashboard use separate terminals.

### One-time setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install -r dashboard\requirements.txt
Copy-Item .env.example .env
```

Set a strong `SITESENTRY_API_TOKEN` in `.env`. Do not commit `.env`, paste secrets into reports, or put API credentials in the browser. Optional settings are described in `.env.example` and `config.py`.

### Start services

Terminal 1:

```powershell
.venv\Scripts\Activate.ps1
python app.py
```

Terminal 2:

```powershell
.venv\Scripts\Activate.ps1
python -m streamlit run dashboard\app.py
```

The dashboard calls the backend at `http://127.0.0.1:5000` by default. Set `SITESENTRY_API_URL` in the dashboard process environment when using another backend address. For a remote backend, the dashboard client requires HTTPS so the bearer token is not sent over remote plain HTTP.

### Submit an API scan

Use the dashboard or send an authenticated request:

```powershell
$headers = @{ Authorization = "Bearer $env:SITESENTRY_API_TOKEN" }
$body = @{ url = "https://example.com"; profile = "advanced" } | ConvertTo-Json
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:5000/api/scans" -Headers $headers -ContentType "application/json" -Body $body
```

The API returns a queued scan ID. Poll `GET /api/scans/<scan_id>` until it reaches a terminal state, then retrieve findings/report. Use a URL without query parameters. Only scan a site within the configured scope and with appropriate authorization.

### Configuration options to know

| Setting | Purpose |
| --- | --- |
| `SITESENTRY_API_TOKEN` | Bearer token for static-token mode |
| `SITESENTRY_AUTH_MODE` | `static_token` or trusted `proxy_identity` |
| `SITESENTRY_ALLOWED_DOMAINS` | Optional comma-separated domain allowlist; empty permits any otherwise-valid public hostname |
| `SITESENTRY_SINGLE_INSTANCE` | `true` uses local queue/limits; `false` requires Redis |
| `SITESENTRY_REDIS_URL` | Shared Redis service for multi-instance queue and limits |
| `SITESENTRY_MAX_PENDING`, `SITESENTRY_MAX_WORKERS` | Queue and worker bounds |
| `SITESENTRY_RATE_PER_MINUTE`, `SITESENTRY_DAILY_QUOTA`, `SITESENTRY_DAILY_QUOTA_PER_CLIENT` | Rate and quota configuration |
| `SITESENTRY_CONNECT_TIMEOUT`, `SITESENTRY_READ_TIMEOUT` | HTTP/TLS network time bounds |
| `SITESENTRY_DATABASE`, `SITESENTRY_REPORT_DIR` | Local SQLite and report paths |
| `AI_PROVIDER`, `GEMINI_API_KEY`, `GEMINI_MODEL`, `XAI_API_KEY`, `GROK_MODEL` | Optional external explanation provider settings |

Multi-instance mode must use the same Redis instance/namespace across app instances. SQLite is still local file persistence; Redis provides shared queue/limit coordination. Multi-instance database durability and high availability require deployment-specific storage/operations beyond the local prototype configuration.

## 14. Training and evaluating models

### Supplied MSWD classifiers

```powershell
python -m ml.train_mswd
```

The default input is `ml/dataset_final.csv`; model bundles and a report are written to `models/mswd-final/`. Inspect `mswd_training_report.json` for dataset hash, label counts, split groups, metrics, and limitations. Re-training replaces deployable bundles: preserve a copy of the old bundle/report if you need a reproducible comparison.

### Configuration-review classifier

1. Collect observations within a lawful/authorized scope.
2. Label with the rules in `ml/labeling_protocol.md`; keep incomplete/conflicting examples uncertain until adjudicated.
3. Prepare a CSV and required provenance companion; schema is in `ml/dataset.schema.json`.
4. Verify the provenance checksum and that domain/organization groups are complete.
5. Train with `python -m ml.train <csv-path> --output models/config_review.joblib`.
6. Review the generated model metadata and compare its held-out metrics with the deterministic rule baseline before deployment.
7. Do not use synthetic rows to claim model quality. Do not split repeated observations or sibling domains across train and test.

## 15. Troubleshooting and result interpretation

| Symptom | Meaning | Suggested action |
| --- | --- | --- |
| `Scan failed. A failed scan is not a security pass.` | Scanner could not finish collection or policy validation; uncollected checks are unknown | Read the stored scan `error`/`errors` and collection code; correct URL/scope/network condition and retry |
| Redirect destination rejected for query string | A redirect included URL query parameters, which this implementation rejects to avoid leaking URL-carried values | Scan a query-free entry URL or review the redirect behavior; do not remove the safety rule without a reviewed secret-handling design |
| DNS resolution failed | Resolver could not provide usable results in the bounded query window | Check hostname spelling, DNS records, resolver access, and retry later |
| TLS verification/handshake failure | Trust, hostname, or TLS negotiation did not complete | Check certificate chain/name/date and server TLS compatibility; this is a collection error, not a pass |
| Connection/read timeout | Target did not respond within configured bounds | Check availability/network latency; increase timeouts only with a capacity/security review |
| Model `not_configured` | Configuration-review artifact is absent | Deterministic scan still works; train only from reviewed data if you need this advisory model |
| Model `incompatible_model` or omitted from model list | Bundle checksum, schema, or runtime compatibility check failed | Restore a matching trusted artifact and manifest/runtime or retrain using the documented pipeline |
| SHAP unavailable | Explanation method/model schema is unsupported or the explanation failed | Use the prediction and deterministic findings; inspect logs/artifact compatibility without treating the prediction as verified evidence |
| AI explanation unavailable | Provider credentials/model/network/schema validation failed | Scan findings and XAI report remain; check provider configuration privately and keep keys out of logs |
| Redis required in multi-instance mode | Shared queue and atomic cross-instance controls need Redis | Start/configure Redis and use the same URL/namespace on all instances, or select single-instance mode for local development |

## 16. Maintenance and contribution instructions

When adding or changing a check:

1. Assign a stable check ID and update the relevant evaluator in `scanner/checks.py` or `scanner/passive_fingerprints.py`.
2. Define exactly what evidence is collected and distinguish `pass`, `warning`, `finding`, `error`, `not_assessed`, and `inconclusive`.
3. State severity separately from confidence and explain false-positive/context caveats.
4. Keep evidence bounded and redact secrets/cookie values. Do not put arbitrary response content into findings.
5. Add a remediation recommendation and a rule version/change note.
6. If appropriate, add risk/standards mapping with a narrow applicability note; do not claim full standards compliance.
7. If a new feature needs external network behavior, define target scope, authorization, redirects, timeout/output/concurrency limits, and isolation before exposing it.
8. Update this guide’s profile matrix and README whenever scan behavior changes.

When changing an ML model:

1. State the prediction target first and keep different targets in separate bundles.
2. Record source, license, label definitions, uncertain cases, collection time, reviewer, feature version, and dataset digest.
3. Split by domain/organization before fitting preprocessing or models; keep the final evaluation group locked.
4. Compare with the deterministic rule and simple baseline; report per-class precision/recall/F1, macro-F1, confusion matrix, false-positive rate, and calibration where probabilities matter.
5. Save preprocessing, schema, SHAP reference rows, runtime versions, training report, and checksum manifest with the model artifact.
6. Keep model results advisory and do not let them change deterministic finding status or severity.

When reporting a scan, use this order:

1. Scan state and selected profile.
2. Checks that ran and checks skipped/not assessed.
3. Most important findings with status, severity, evidence, and suggested fix.
4. Scan errors and limitations.
5. Risk score (if shown), explicitly called advisory prioritization.
6. ML/SHAP/LLM explanation (if present), explicitly labeled advisory/model-generated.

## 17. Implementation boundaries and known limitations

- This is a bounded prototype, not a security certification or a full vulnerability scanner.
- A single response and negotiated TLS connection do not represent every route, user state, IP address, or server configuration.
- DNS results are observations and may change; they do not establish DNSSEC or infrastructure security.
- Header checks are not browser/application behavior tests; cookie expectations and optional headers depend on application context.
- Advanced TLS examines the negotiated protocol/cipher only, not every supported server option.
- Technology/WAF/service signatures may be missing or spoofed. Passive templates are small and do not replace a reviewed vulnerability-testing program.
- The MSWD label mapping is inferred, and its distribution/source can bias results. Model metrics describe only the reported held-out partition.
- The configuration-review model requires a separate human-reviewed dataset that is not supplied by the MSWD dataset.
- SHAP explains model behavior relative to reference data; it does not explain causal security impact.
- Optional LLM explanations can be wrong; deterministic evidence/rules remain authoritative.
- Production multi-tenant deployments need reviewed isolation, egress controls, shared storage/queue operations, monitoring, backups, key rotation, and deployment-specific verification.

## 18. Source-of-truth files

- Scan orchestration: [`scanner/engine.py`](../scanner/engine.py)
- HTTP/TLS connection safety: [`scanner/transport.py`](../scanner/transport.py)
- URL and scope policy: [`scanner/url_validation.py`](../scanner/url_validation.py)
- Deterministic HTTP/TLS checks: [`scanner/checks.py`](../scanner/checks.py)
- Advanced passive fingerprints: [`scanner/passive_fingerprints.py`](../scanner/passive_fingerprints.py)
- DNS observation: [`scanner/dns_checks.py`](../scanner/dns_checks.py)
- Risk score/mappings: [`scanner/risk.py`](../scanner/risk.py)
- API/auth/queue/routes: [`app.py`](../app.py), [`config.py`](../config.py), [`rate_limit.py`](../rate_limit.py)
- Dashboard/API client: [`dashboard/app.py`](../dashboard/app.py), [`dashboard/scanner.py`](../dashboard/scanner.py)
- Persistence: [`storage.py`](../storage.py)
- MSWD training: [`ml/train_mswd.py`](../ml/train_mswd.py)
- Configuration-review training: [`ml/train.py`](../ml/train.py)
- Feature extraction: [`ml/features.py`](../ml/features.py)
- Model inference/deployment integrity: [`ml/mswd_predict.py`](../ml/mswd_predict.py), [`ml/deployment.py`](../ml/deployment.py)
- SHAP and scan XAI report: [`xai/feature_attribution.py`](../xai/feature_attribution.py), [`xai/report.py`](../xai/report.py)
- Dataset review protocol: [`ml/labeling_protocol.md`](../ml/labeling_protocol.md)
- Short user-facing setup: [`README.md`](../README.md)

