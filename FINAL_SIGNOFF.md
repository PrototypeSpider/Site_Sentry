# SiteSentry final project sign-off

Updated: 2026-10-19

## Verification summary

The local implementation and test suite are complete for the checks listed below. This is not a production-readiness certification: live Redis multi-instance verification, real Gemini/Grok verification, and configuration-review model evaluation still need their external prerequisites and recorded evidence.

Latest local verification:

- `pytest -q`: **44 passed, 3 skipped**. The skipped tests require an isolated Redis service and `SITESENTRY_TEST_REDIS_URL`.
- `python -m compileall -q scanner reports ml integrations xai app.py storage.py config.py`: passed.
- Source checks and local tests cover URL/scope validation, destination pinning and redirect rejection, bounded requests/queues, scan failure states, authentication, cancellation, parsers, AI sanitization/schema/fallback, ML input/provenance validation, and report generation.
- The repository includes regression tests; it does not yet include retained production Redis output, a successful live provider transcript, or a reviewed configuration-review dataset.

## Status key

- **Implemented and locally verified**: code exists and local tests pass.
- **Implemented; deployment evidence pending**: code/test harness exists, but live infrastructure or external credentials are needed.
- **Pending external data/review**: must not be claimed complete without real observations and qualified review.
- **Not applicable / documented limitation**: feature is not enabled or supported in the current passive-scanner deployment.

## Core application and backend

- [x] Python environment and dependencies documented (`requirements.txt`, `dashboard/requirements.txt`; runtime pins for deployed models).
- [x] Flask API request validation and response handling covered by tests; documented in `README.md`.
- [x] Environment-driven settings; `.env` ignored and credential patterns checked in the staged/release source.
- [x] Structured logging, generic API error handling and authenticated health endpoint implemented.
- [x] SQLite migrations, schema version 4, indexes, and foreign-key enforcement implemented.
- [x] Bounded local scan queue/workers and shared Redis queue mode implemented.
- [x] Authenticated scan history is isolated by identity; migration adds owner IDs and regression tests cover list/detail isolation.

## Target validation and scan safety

- [x] HTTP/HTTPS schemes, hostnames, ports, URL credentials, allowlist and public destination checks implemented and tested.
- [x] DNS-rebinding mitigation pins connections to validated addresses; redirects are revalidated and kept in scope.
- [x] Connection/read timeout, response-size, queue, worker and API request-size limits implemented.
- [x] Failed scans remain error/inconclusive and do not become security passes.
- [x] Queued cancellation and worker dequeue transition are serialized and covered by tests; retry behavior is not implemented because scans are not automatically retried.
- [ ] Production egress restrictions and least-privilege isolation for external tools must be applied by the deployment operator.

## Authentication, shared rate limits and quotas

- [x] Bearer-token or trusted-proxy identity authentication is enforced on protected endpoints.
- [x] Redis Lua rate/quota limiter and Redis-backed scan queue are implemented; multi-instance mode refuses configuration without Redis and strong authentication.
- [x] Local per-instance rate/quota behavior is covered in tests.
- [ ] Run and retain `python -m integrations.verify_redis_multi_instance` output against an isolated Redis service to verify cross-instance limits/quotas and authentication.
- [ ] Record Redis outage and recovery behavior in the deployment environment. Redis failure currently causes requests to fail closed; recovery after Redis returns has no retained live evidence.

## Scanner, findings and integrations

- [x] HTTPS reachability, redirect/status/content-type behavior, TLS chain/hostname/expiry/protocol/cipher, security headers, and bounded DNS evidence implemented.
- [x] Findings include stable check IDs, status, severity, evidence, timestamps, source/tool version where applicable, rule version and limitations.
- [x] Header directives are evaluated; finding normalization preserves/deduplicates evidence and contradictory external observations remain inconclusive.
- [x] Optional tool adapters use fixed arguments, bounded output/runtime and parsers; external tool execution is opt-in and not run as part of the passive scan.
- [ ] Live binary checks for testssl.sh, WhatWeb, wafw00f, Nmap, Nikto, Nuclei, SSLyze and ZAP depend on approved binaries, reviewed scope and isolated workers; they have not been run here.
- [x] Remediation guidance and limitations are emitted with findings; known unsupported checks are documented in `README.md`.

## ML and deep learning

- [x] Supplied MSWD malicious-site dataset trained/evaluated separately; deployable LR, Random Forest and MLP artifacts and checksummed manifests are in `models/mswd-final/`.
- [x] MSWD report records grouped holdout metrics, excluded rows, feature/data versions and limitations. Semantic mapping of numeric classes remains an assumption needing dataset-author confirmation.
- [x] API/dashboard model outputs are advisory and separate from verified scanner findings.
- [ ] Configuration-review dataset with real observations, provenance and qualified human-reviewed labels is not available. MSWD labels do not satisfy this target.
- [ ] Train/evaluate the configuration-review model and its deterministic-rule baseline after obtaining reviewed data.
- [ ] Retain a DL model for configuration-review only if domain-held-out results show meaningful repeatable improvement over the simple baseline.
- [ ] Run the final locked domain-held-out evaluation and retain precision, recall, macro-F1, confusion matrix, false-positive rate, split manifest and limitations.

## Explainability and Gemini/Grok

- [x] Deterministic rule explanations cite the exact normalized finding evidence and remediation.
- [x] SHAP is used with supported trained tabular model bundles; report identifies model/version and treats attribution as non-causal. It is unavailable for unsupported or absent models.
- [x] Gemini/Grok provider adapters validate structured responses, bound and redact normalized evidence, use timeout/retry handling, and preserve deterministic scan results if provider calls fail.
- [x] Automated tests cover sanitized payloads, malformed output, errors, and deterministic fallback.
- [ ] Rotate any credentials exposed in earlier configuration/messages before use; configure a supported provider/model and run `python -m integrations.verify gemini` or `python -m integrations.verify grok` with rotated credentials.
- [ ] Retain redacted live smoke-test output. No provider credentials or real provider response were available for this local sign-off.

## Reports, persistence and API

- [x] Scan creation, status, findings, explanations, cancellation, history, XAI, JSON and PDF report routes are implemented and locally covered.
- [x] Scan identity, state transitions, canonical JSON findings/evidence/remediation/limitations, report digest and PDF-from-canonical-result behavior are implemented.
- [x] History is filtered by authenticated identity after schema migration 4.
- [ ] Production backup/restore, retention and cleanup procedures must be configured and tested by deployment owner; SQLite is intended for initial/single-instance deployments.
- [ ] Multi-user hosted deployment requires production identity provisioning, shared Redis, isolated workers, monitoring and network egress controls.

## Release evidence artifacts

| Area | Evidence in repository | Remaining evidence |
| --- | --- | --- |
| Deployment | `.env.example`, `README.md`, model runtime pins | Redacted live deployment configuration and environment-specific security review |
| Redis | `integrations/verify_redis_multi_instance.py`, automated Redis tests | Successful two-instance output plus outage/recovery record |
| Scanner | `tests/` and current pytest result | Retained CI/release run and authorized live-tool integration run where tools are enabled |
| Dataset | `ml/dataset.schema.json`, `ml/labeling_protocol.md` | Reviewed configuration dataset, provenance, reviewer record and locked split |
| ML/DL | MSWD training report and checksummed artifacts | Configuration-review baseline/model held-out report; confirm MSWD label mapping with authors |
| AI | Provider adapters and mocked contract tests | Successful live Gemini/Grok smoke test with rotated credentials, secrets redacted |
| Release | Source and model bundles are versioned | Tag/version, dependency lock for application and dashboard, dependency/secrets scan, deployment backup/recovery evidence |

## Sign-off decision

**Implementation-ready prototype; production verification pending.** Do not mark the deployment production-ready until the outstanding Redis, reviewed-data/model, live-provider, and deployment-specific isolation/backup evidence is attached. No scan result or ML prediction should be represented as proof that a website is secure or exploitable.
