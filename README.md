# SiteSentry backend

Passive website security assessment prototype with a Flask backend and Streamlit dashboard.

For the complete architecture, scan lifecycle, check/model logic, XAI, setup instructions, and troubleshooting guide, see [SiteSentry Project Architecture and Operations Guide](docs/SiteSentry_Project_Architecture_and_Operations_Guide.md).

## Implemented

For the line-by-line checklist and explicit pending items, see [CHECKLIST_STATUS.md](CHECKLIST_STATUS.md).

- Flask API with health, asynchronous scan submission, status/history, findings, deterministic explanations, cancellation, and JSON/PDF report endpoints.
- Configurable bearer-token authentication, optional approved-domain allowlist, per-process limits for single-instance use or atomic shared rate/quota limits with Redis, bounded queue/workers, request size limit, and explicit network timeouts. The client cannot assert authorization through a request field; deployment scope is enforced by backend settings.
- URL validation for HTTP/HTTPS and standard ports; rejects embedded credentials, query strings (including query-bearing redirects), malformed hosts, private/reserved/loopback/link-local IPs, and out-of-scope names. Queries are excluded to avoid sending URL-carried secrets and to keep findings/history free of sensitive parameter values.
- Connection-time IP pinning while preserving original host SNI and TLS hostname verification; manually follows redirects only after validating each new destination.
- DNS A/AAAA/CNAME/NS/TXT observations; TLS chain/hostname verification, certificate validity/expiry, negotiated TLS version/cipher; HTTP status, content type, redirects, bounded response bytes; security-header checks including directives.
- Normalized findings with stable IDs, evidence, status (`pass`, `finding`, `warning`, `fail`, `error`, `not_assessed`, `inconclusive`), severity, separate advisory confidence and evidence-backed risk prioritization, recommendation, partial standards mapping, rule version, timestamp, ML/XAI/AI fields. Related findings are deduplicated by check family in the overall score. A failed scan does not pass checks.
- HSTS max-age/subdomain/preload observations, CSP source-policy review, and cookie Secure/HttpOnly/SameSite attribute checks. Cookie names and values are not emitted as finding evidence; expected attributes remain application-dependent.
- Advanced profile applies in-process passive fingerprints inspired by testssl.sh, WhatWeb, Nmap, wafw00f, Nikto, and Nuclei methods. These inspect the existing response/TLS handshake only and do not invoke the external tools, crawl, probe ports, or send payloads.
- SQLite scan history and audit events with schema version 5, identity-scoped scan ownership and finding workflow, JSON integrity digest, PDF export from the canonical stored result.
- Owner-protected remediation workflow for marking findings acknowledged/fixed, with bounded notes. A “fixed” label is only confirmed after a same-host/port/path rescan reports the check as passing. Historical comparisons report new, resolved, recurring, changed and unchanged checks.
- A bounded, passive CI command with explicit authorization confirmation, deterministic exit codes and configurable severity/risk thresholds.
- Optional calibrated Logistic Regression baseline for a defined advisory configuration-review label, grouped holdout by target group, per-class precision/recall/F1, macro F1, confusion matrix, FPR when a negative label is present, model/data/feature version and dataset hash. Predictions remain advisory. SHAP attributions are available as non-causal model explanations.
- Optional Gemini/Grok interface; bounded/redacted evidence, structured response validation, bounded client timeouts/retries, deterministic fallback. Scan data remains available if AI fails.
- Optional research-only MLP comparison. Do not use it unless it beats the logistic baseline on representative labeled data.
- Fixed-command opt-in adapters for OpenSSL, testssl.sh, WhatWeb, wafw00f, Nmap, Nikto, curated-template Nuclei, SSLyze, and ZAP; explicit executable directory, scope/authorization gates, timeouts, bounded output, parsers, and conflict-preserving normalization. The adapters are not automatically invoked by passive scans.
- Optional Redis-backed atomic cross-instance rate limits, quotas, and shared scan queue (`SITESENTRY_REDIS_URL`) and trusted reverse-proxy identity mode. Multi-instance mode is rejected without Redis and strong token/proxy identity settings.
- Dataset collection and reviewer guidance in `ml/labeling_protocol.md`; the trainer requires a checksummed provenance companion.
- Live provider smoke check loads `.env`: `python -m integrations.verify gemini` or `python -m integrations.verify grok`; uses synthetic evidence and redacts provider error bodies.
- Redis integration check: set `SITESENTRY_TEST_REDIS_URL` to an isolated Redis database, then run `python -m integrations.verify_redis_multi_instance`; creates two app instances, checks shared rate and client quotas plus authentication, and stubs scanning to avoid network access.
- Trained MSWD Logistic Regression, Random Forest, and MLP artifacts are under `models/mswd-final/`. Each deployable bundle includes preprocessing, feature schema, SHAP background rows, a SHA-256 manifest, and pinned runtime requirements. The authenticated model API and dashboard workbench provide per-model predictions and SHAP explanations; outputs remain separate from deterministic scan findings.

## Setup and API

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Set `SITESENTRY_API_TOKEN` before starting the service; the authenticated admin token protects scan submission. Leave `SITESENTRY_ALLOWED_DOMAINS` empty to allow scans of any public hostname, or set a comma-separated hostname allowlist to restrict scope. Private, loopback, link-local, and reserved IP destinations remain blocked. `SITESENTRY_SINGLE_INSTANCE=true` uses local limits and a local queue. For multiple instances set it false and configure `SITESENTRY_REDIS_URL`; this selects atomic shared rate/quota limits and a shared Redis scan queue. `SITESENTRY_REDIS_NAMESPACE` isolates queue and limiter keys for each deployment. Proxy identity mode requires a trusted TLS-terminating proxy to strip client-supplied identity headers and set `X-Authenticated-User` and `X-Forwarded-Proto: https`.

```powershell
python app.py
```

## Terminal CLI

SiteSentry also installs as a terminal-native command. The CLI reuses the existing scanner and offers **Advanced only** as its single/default profile. It does not render a dashboard, and it does not call external scanners. Every scan remains passive and bounded.

Install from the project root:

```powershell
python -m pip install -e .
sitesentry --help
```

Run an authorized scan and save the canonical JSON report to the default report directory:

```powershell
sitesentry scan https://example.com --authorized
```

The `--authorized` flag is an explicit operator confirmation. `SITESENTRY_ALLOWED_DOMAINS`, when configured, remains enforced; private, loopback, link-local, reserved, and prohibited destinations are still blocked. URL query strings are rejected. The CLI uses the configured connect/read timeouts and stores local CLI history in the configured SQLite database.

Useful commands:

```powershell
sitesentry scan --help
sitesentry scan https://example.com --authorized --format json --output reports/example.json
sitesentry history
sitesentry report <SCAN_ID>
sitesentry report reports/example.json --format json
sitesentry config show
sitesentry doctor
sitesentry check-config
sitesentry --version
```

The `sitesentry scan` command accepts no `--profile` option: all scans run Advanced checks. The older CI wrapper accepts only `--profile advanced`. The Flask API and Streamlit dashboard retain their own profile selector. `--format json` writes the normalized report to stdout; `--output` saves a JSON copy. Terminal text output is intended for operators, while JSON is suitable for pipelines.

Exit codes: `0` means the scan completed (including when findings exist, unless a threshold was requested); `1` means `--fail-on` was reached; `2` means scan/runtime/storage failure; `3` means invalid input, rejected scope, or missing authorization confirmation. Example CI gate: `sitesentry scan https://example.com --authorized --format json --fail-on high`.

Install optional AI provider libraries only when needed with `python -m pip install -e ".[ai]"`; providers remain optional to scan execution.

### Dashboard

The dashboard is a server-side API client. It does not run its own scanner and never sends the API token to browser JavaScript. Configure `SITESENTRY_API_TOKEN` in the root `.env` file and run the backend and dashboard in separate terminals from the repository root:

```powershell
python app.py
python -m pip install -r dashboard/requirements.txt
python -m streamlit run dashboard/app.py
```

The dashboard defaults to `http://127.0.0.1:5000`; set `SITESENTRY_API_URL` on the dashboard process when the backend is hosted elsewhere. The backend authentication and optional domain allowlist remain authoritative.

Endpoints: `GET /api/health`, `POST /api/scans`, `GET /api/scans`, `GET /api/scans/<id>`, `GET /api/scans/<id>/findings`, `GET /api/scans/<id>/workflow`, `PUT /api/scans/<id>/findings/<check-id>/workflow`, `GET /api/scans/<current-id>/compare/<baseline-id>`, `GET /api/scans/<id>/explanations`, `GET /api/scans/<id>/xai-report`, `GET /api/scans/<id>/report?format=json|pdf`, `POST /api/scans/<id>/cancel`, `GET /api/models`, and `POST /api/models/<model-id>/predict`.

Finding workflow updates accept `{"status":"open|acknowledged|fixed","note":"optional, up to 500 characters"}`. `open` removes the saved workflow state. History, comparison, report and workflow routes require the authenticated scan owner. Comparisons reject different hostnames, ports, or paths. Standards links are partial guidance and do not establish full OWASP ASVS compliance.

Choose `profile` as `quick`, `standard`, or `advanced` in `POST /api/scans`. Quick checks core HTTPS/TLS and selected high-value headers without DNS. Standard runs the full existing DNS, TLS, and header checks. Advanced adds negotiated TLS protocol/cipher and CSP directive review plus passive HTTP technology/service fingerprints, heuristic WAF header indicators, and curated evidence-only web configuration templates. Those in-process checks are inspired by testssl.sh, WhatWeb, Nmap, wafw00f, Nikto, and Nuclei detection approaches; they do not invoke those programs, make extra requests, crawl, probe ports, or send test payloads. The selected profile is persisted in scan history and report metadata. Responses include checks passed, findings to review, high/critical findings, TLS verification state, and scan duration. Findings in the dashboard are grouped into Pass/Warn/Fail statuses and include evidence and recommended fixes.

Example request:

```json
{"url":"https://www.example.com","profile":"standard"}
```

Send `Authorization: Bearer <SITESENTRY_API_TOKEN>` for every API endpoint, including health.

### Bounded CI scan

An authorized CI job can run the same passive checks and use deterministic exit codes. The `--authorized` flag is mandatory; `SITESENTRY_ALLOWED_DOMAINS` remains enforced when configured. JSON is written to stdout and optionally to a file. The command does not enable external tools or active exploitation.

```powershell
python -m integrations.ci_check --url https://example.com --profile advanced --authorized --fail-on high --min-risk 0 --output sitesentry-report.json
```

Exit codes: `0` checks completed below the configured threshold, `1` threshold met, `2` scan did not complete. Use `--fail-on none --min-risk 60` to make the score threshold the gate. Risk score and severity remain separate.

## ML training data required

No labeled configuration-review dataset is available yet, so no configuration-review model performance is claimed. The supplied MSWD dataset supports the separate malicious-site classifier described below. To train the configuration-review baseline, prepare a UTF-8 CSV with at least 20 human-reviewed rows, four or more distinct `target_group` values, both classes represented in train and held-out groups, and a companion `<csv-name>.provenance.json` based on `ml/dataset.schema.json`:

```csv
target_group,label,https,tls_verified,tls_days_remaining,headers_json
site-a,review,1,true,120,"{\"Strict-Transport-Security\":\"max-age=31536000\",\"X-Content-Type-Options\":\"nosniff\"}"
```

Provenance must identify source, collection time, reviewer, label policy, target definition, and SHA-256 of the exact CSV bytes. Training refuses absent or mismatched provenance. `label` must represent your documented configuration-review classification, not vulnerability/exploitability. `target_group` should group observations by site or organization so records from one target cannot leak across the split. Use real, lawfully collected and reviewed labels; synthetic rows can only exercise code and cannot support accuracy claims.

```powershell
python -m ml.train data/labeled_scans.csv --output models/config_review.joblib
```

The scanner automatically returns `not_configured` until that model exists. Once trained, the configuration-review model is checksum-manifested and produces SHAP explanations during scans. DL is a research comparison in `ml/deep_learning.py`, not used by scans.

Configuration-review ML calibration and drift tracking remain contingent on real, reviewed configuration observations. The supplied MSWD malicious-site data is a different target and must not be used to claim configuration-review quality.

### Supplied MSWD malicious-site data

The supplied `ml/dataset_final.csv` and ZIP are the same 5,013-record MSWD dataset. `python -m ml.train_mswd` trains Logistic Regression, Random Forest, and MLP classifiers; outputs go to `models/mswd-final/`. Each `.joblib` bundle has a matching `.joblib.manifest.json` checksum/runtime record and the directory has a `requirements-deploy.txt` lockfile. The training report records the dataset hash, excluded unlabeled rows, hostname-group holdout, metrics, and limitations. The authenticated `/api/models` endpoint lists checksum-verified artifacts; `/api/models/<model-id>/predict` accepts the model's feature JSON and returns the prediction plus SHAP contributions. The dashboard's Advisory model workbench exposes the schema and this prediction flow. The dataset page describes benign and malicious URLs and lists CC BY 4.0, but does not document the numeric mapping; the pipeline assumes 0=benign and 1=malicious based on the class distributions and threat-indicator alignment. Confirm that mapping with the dataset authors before making product claims. Safe Browsing and VirusTotal features, hashes, IPs, and raw domain strings are excluded from model predictors. This is a separate advisory website-classification task; its result never changes rule findings.

## Optional AI explanations

Set `AI_PROVIDER=gemini` with `GEMINI_API_KEY` and `GEMINI_MODEL`, or `AI_PROVIDER=grok` with `XAI_API_KEY` and `GROK_MODEL`. AI is optional and never changes rule status or severity. Never pass credentials, authenticated scans, or unnecessary page content to an external provider.

## Tools and supported scope

The baseline uses Python `ssl`, HTTP, and DNS libraries only. `ssl` is the TLS implementation; the advanced profile also applies bounded in-process heuristics inspired by common scanner methods. Standalone OpenSSL and external programs (testssl.sh/WhatWeb/wafw00f/Nmap/Nikto/Nuclei/SSlyze/ZAP) are not automatically invoked. Active or third-party command integrations need a deployment-specific allowlist, isolated least-privilege workers, reviewed parsers, and explicit authorized scope. Nmap/Nikto/Nuclei/ZAP are intentionally not exposed through arbitrary client arguments.

The scanner is passive and is not proof that a target is secure. It does not crawl pages, authenticate, test application behavior, or establish exploitability. Header absence is configuration evidence only. Do not deploy the in-process worker queue as a multi-tenant hosted service without external worker isolation, persistent queueing, shared rate controls, monitoring, and network egress controls.

## Development checks

```powershell
pytest -q
python -m compileall -q scanner reports ml integrations xai app.py storage.py config.py
```
