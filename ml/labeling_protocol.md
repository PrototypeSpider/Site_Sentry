# SiteSentry configuration-review labeling protocol

## Prediction target

Label a site observation for **configuration review priority**, not vulnerability or exploitability:

- `compliant`: the reviewed observation meets the team's declared baseline for all included checks.
- `review`: one or more declared baseline checks need human review or remediation.
- `uncertain`: evidence is incomplete, contradictory, or context-specific. Exclude this label from the first binary model; retain it for adjudication and report it separately.

The label is an assessment of this recorded observation at a specific collection time. It is not a timeless property of a domain.

## Collection record

For every observation, preserve an opaque record ID, registrable-domain group ID, collection timestamp, scanner/rule version, authorized source, target URL (restricted/redacted as appropriate), response/TLS/DNS evidence, normalized features, and reviewer decision. Do not include credentials or session data. Store the raw evidence separately with access controls and link it with a content digest.

The CSV trainer currently consumes `target_group,label,https,tls_verified,tls_days_remaining,headers_json`. Keep collection date, source, rubric version, reviewer ID, and CSV SHA-256 in the required `.provenance.json` companion. Keep a separate audit record linking the dataset digest to the consent/scope record; never put personal data or secrets in the model artifact.

## Reviewer rubric

1. Review the normalized observation and its limitations, not an ML prediction.
2. Treat a check error or `not_assessed` as `uncertain`, not as compliant.
3. Apply a versioned organizational baseline. Do not label a site `review` merely because an optional header is absent unless the baseline says that header is expected for this application.
4. Two reviewers independently label each record. Record a reason code per check and a short rationale.
5. Resolve disagreement through a third reviewer. If unresolved, keep `uncertain` and exclude it from supervised binary training.
6. Sample across domains, hosting providers, application types, and time. Avoid collecting many near-duplicate paths from one site.

## Split and evaluation policy

Group all observations from one registrable domain/organization into a single split. Do not let the same target or repeated crawl appear in both train and test. Lock a final domain-held-out test set before feature/model iteration. Report per-class precision, recall, F1, macro F1, confusion matrix, and false-positive rate for the agreed negative class. Evaluate calibration separately and monitor class prevalence. Compare ML against the deterministic rule baseline and a simple majority baseline. Only consider deep learning if there is enough independent domain-level data and its improvement is meaningful and repeatable.

## Acceptance

Qualified reviewers, consent/scope, sampling frame, rubric version, label counts, domain-group split, and the locked test set must be documented before training. Synthetic fixture data may test code only and must never be included in evaluation claims.
