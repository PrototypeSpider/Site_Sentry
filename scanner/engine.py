"""Coordinates safe passive collection and deterministic assessment rules."""

from __future__ import annotations

from datetime import datetime, timezone

from .checks import evaluate_advanced_observation, evaluate_observation
from .dns_checks import observe_dns
from .models import Finding, ScanResult
from .passive_fingerprints import evaluate_passive_fingerprints
from ml.features import extract_features
from ml.predict import assess
from xai.feature_attribution import explain_linear
from integrations.explainer import get_provider, sanitize_evidence
from .transport import SafeTransport, SafeTransportError
from .url_validation import TargetValidationError, report_safe_url, validate_target


class Scanner:
    def __init__(self, *, timeout: tuple[float, float] = (3.05, 7.0), allowed_domains: set[str] | None = None):
        self.allowed_domains = {domain.lower().rstrip(".") for domain in allowed_domains} if allowed_domains else None
        self.transport = SafeTransport(timeout=timeout, allowed_domains=self.allowed_domains)

    def scan(self, url: str, *, profile: str = "standard") -> ScanResult:
        if profile not in {"quick", "standard", "advanced"}:
            raise ValueError("profile must be quick, standard, or advanced")
        started = datetime.now(timezone.utc).isoformat()
        findings: list[Finding] = []
        errors: list[str] = []
        try:
            target = validate_target(url, allowed_domains=self.allowed_domains)
            dns = observe_dns(target.hostname) if profile != "quick" else {"hostname": target.hostname, "records": {}, "errors": {}, "status": "skipped_by_profile"}
            observation = self.transport.observe(target)
            findings = evaluate_observation(observation)
            if profile == "quick":
                quick_checks = {"https.reachable", "tls.certificate_validation", "tls.certificate_expiry",
                    "header.hsts", "header.csp", "header.x_content_type_options", "header.clickjacking_protection"}
                findings = [finding for finding in findings if finding.check_id in quick_checks]
            elif profile == "advanced":
                findings.extend(evaluate_advanced_observation(observation))
                findings.extend(evaluate_passive_fingerprints(observation))
            feature_record = {"https": observation.final_url.lower().startswith("https://"), "tls_verified": (observation.tls or {}).get("verified") is True,
                "tls_days_remaining": _tls_days_remaining((observation.tls or {}).get("not_after")), "headers": observation.headers}
            ml_result = assess(feature_record, "models/config_review.joblib")
            model_xai = explain_linear(feature_record, "models/config_review.joblib") if ml_result["status"] == "advisory" else None
            for finding in findings:
                finding.ml_assessment = {**ml_result, "feature_preview": extract_features(feature_record) if ml_result["status"] == "advisory" else None}
                finding.xai = model_xai if model_xai is not None else {"method": "rule_evidence", "status": "available", "rule_id": finding.check_id,
                    "evidence": finding.evidence, "explanation": finding.explanation, "contributions": []}
            provider = get_provider()
            ai_explanations = {}
            if provider:
                for finding in findings:
                    try:
                        finding.ai_explanation = {"status": "available", "provider": provider.__class__.__name__,
                            "content": provider.explain(sanitize_evidence({"check_id": finding.check_id, "status": finding.status,
                                "severity": finding.severity, "evidence": finding.evidence, "explanation": finding.explanation,
                                "recommendation": finding.recommendation}))}
                    except Exception:
                        finding.ai_explanation = {"status": "unavailable", "provider": provider.__class__.__name__,
                            "content": {"summary": finding.explanation, "evidence": finding.evidence, "potential_impact": "See deterministic finding.",
                                "remediation": finding.recommendation, "limitations": "Optional AI explanation failed; deterministic result retained."}}
                    ai_explanations[finding.check_id] = finding.ai_explanation
            if observation.redirect_chain:
                initial_scheme = target.url.split(":", 1)[0].lower()
                final_scheme = observation.final_url.split(":", 1)[0].lower()
                status = "pass" if initial_scheme == "http" and final_scheme == "https" else ("finding" if initial_scheme == "http" else "not_assessed")
                findings.append(Finding("http.https_redirect", "HTTP-to-HTTPS redirect", status,
                    "informational" if status in {"pass", "not_assessed"} else "medium",
                    f"Initial scheme={initial_scheme}; final scheme={final_scheme}; chain={[report_safe_url(item) for item in observation.redirect_chain]}.",
                    "HTTP-to-HTTPS redirects help move cleartext requests to HTTPS. This check assesses only the observed URL path.",
                    "Redirect HTTP requests to HTTPS and retain HSTS for future browser visits." if status == "finding" else "Confirm every HTTP entry point redirects to HTTPS."))
                redirect_finding = findings[-1]
                redirect_finding.ml_assessment = {**ml_result, "feature_preview": None}
                redirect_finding.xai = {"method": "rule_evidence", "status": "available", "rule_id": redirect_finding.check_id,
                    "evidence": redirect_finding.evidence, "explanation": redirect_finding.explanation, "contributions": []}
                redirect_finding.ai_explanation = {"status": "not_configured", "provider": None, "content": None}
                ai_explanations[redirect_finding.check_id] = redirect_finding.ai_explanation
                findings.append(Finding("http.redirect_chain", "Redirect handling", "pass", "informational",
                    f"Safely followed {len(observation.redirect_chain)} redirect(s); final URL: {report_safe_url(observation.final_url)}.",
                    "Each redirect target was revalidated against public-address and domain-scope policy.",
                    "Keep redirects within the authorized target scope."))
                redirect_finding = findings[-1]
                redirect_finding.ml_assessment = {**ml_result, "feature_preview": None}
                redirect_finding.xai = {"method": "rule_evidence", "status": "available", "rule_id": redirect_finding.check_id,
                    "evidence": redirect_finding.evidence, "explanation": redirect_finding.explanation, "contributions": []}
                redirect_finding.ai_explanation = {"status": "not_configured", "provider": None, "content": None}
                ai_explanations[redirect_finding.check_id] = redirect_finding.ai_explanation
            modules = ["http_headers", "tls"]
            if profile != "quick": modules.insert(0, "dns")
            if profile == "advanced": modules.extend(["tls_advanced_rules", "passive_security_fingerprints"])
            return ScanResult(target=report_safe_url(observation.final_url), scan_status="completed", findings=findings,
                started_at=started, completed_at=datetime.now(timezone.utc).isoformat(), modules_executed=modules,
                metadata={"dns": dns, "http": {"status_code": observation.status_code, "content_type": observation.headers.get("content-type"),
                    "redirect_chain": [report_safe_url(item) for item in observation.redirect_chain],
                    "final_url": report_safe_url(observation.final_url), "body_bytes_read": observation.body_bytes_read, "body_truncated": observation.body_truncated},
                    "tls": observation.tls, "ai_explanations": ai_explanations, "scan_profile": profile},
                limitations=["Passive single-response assessment only; no crawling, exploit testing, port scanning, or vulnerability proof.",
                             "Connections are pinned to validated public IP addresses; DNS is checked again before every redirect connection.",
                             "Header checks inspect the final response only; missing headers do not by themselves prove exploitability."])
        except TargetValidationError as exc:
            errors.append(str(exc))
            findings.append(Finding("scan.request", "Safe scan request", "error", "informational", str(exc),
                                    "The requested scan did not complete under the configured target or transport policy.",
                                    "Correct the URL or assess a public target within the authorized scope."))
            return ScanResult(target=report_safe_url(url) if isinstance(url, str) else "", scan_status="error", findings=findings,
                started_at=started, completed_at=datetime.now(timezone.utc).isoformat(), errors=errors,
                limitations=["No target checks are counted as passed when target validation or collection fails."])
        except SafeTransportError as exc:
            errors.append(str(exc))
            findings.append(Finding(f"collection.{exc.code}", "Network collection", "error", "informational", str(exc),
                "The scan failed during a specific collection stage; uncollected checks are not reported as passed.",
                "Resolve the reported DNS, TLS, connection, read, redirect, or HTTP collection condition and retry if authorized.", source=exc.code))
            return ScanResult(target=report_safe_url(url) if isinstance(url, str) else "", scan_status="error", findings=findings,
                started_at=started, completed_at=datetime.now(timezone.utc).isoformat(), errors=errors,
                modules_executed=["dns"] if "dns" in locals() else [], metadata={"collection_error_code": exc.code},
                limitations=["No target checks are counted as passed when collection fails."])


def scan_url(url: str, *, allowed_domains: set[str] | None = None) -> dict:
    """Convenience function returning a JSON-serializable result dictionary."""
    return Scanner(allowed_domains=allowed_domains).scan(url).to_dict()


def _tls_days_remaining(not_after: object) -> int | None:
    if not isinstance(not_after, str):
        return None
    from email.utils import parsedate_to_datetime
    try:
        return (parsedate_to_datetime(not_after) - datetime.now(timezone.utc)).days
    except (TypeError, ValueError, OverflowError):
        return None
