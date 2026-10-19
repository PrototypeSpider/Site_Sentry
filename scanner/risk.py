"""Evidence-backed, explicitly advisory finding prioritization."""

from __future__ import annotations

from collections import defaultdict


SEVERITY_WEIGHT = {"critical": 90, "high": 75, "medium": 50, "low": 25, "informational": 5}
UNRESOLVED = {"finding", "warning", "fail", "error", "inconclusive"}
IMPACT_BY_CHECK = {
    "tls.certificate_validation": 1.0, "tls.certificate_expiry": 0.9, "tls.protocol_version": 0.95,
    "tls.cipher_strength": 0.85, "header.csp": 0.9, "header.csp_directives": 0.9,
    "header.cookie_security": 0.95, "header.clickjacking_protection": 0.75,
    "http.https_redirect": 0.8, "https.reachable": 0.9,
}

# Mapping is intentionally narrow and includes applicability notes rather than
# asserting compliance with a full control framework.
STANDARDS = {
    "header.hsts": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.4.1 HSTS", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/04-browser-security-mechanism-headers", "applicability": "Observed response only. ASVS specifies at least one year and subdomains for L2+; SiteSentry's local rule is a partial check, not conformance."}],
    "header.csp": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.4.3 Content-Security-Policy", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/04-browser-security-mechanism-headers", "applicability": "Presence and bounded directive checks only; does not establish the ASVS allowlist/nonce/hash requirements or test application flows."}],
    "header.csp_directives": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.4.3 Content-Security-Policy", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/04-browser-security-mechanism-headers", "applicability": "Bounded review of script sources; does not validate every directive or the ASVS control."}],
    "header.clickjacking_protection": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.4.6 CSP frame-ancestors", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/04-browser-security-mechanism-headers", "applicability": "An X-Frame-Options fallback is reported for compatibility but does not establish the ASVS CSP frame-ancestors requirement."}],
    "header.x_content_type_options": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.4.4 X-Content-Type-Options", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/04-browser-security-mechanism-headers", "applicability": "Inspects only the response captured by the selected scan profile."}],
    "header.referrer_policy": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.4.5 Referrer-Policy", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/04-browser-security-mechanism-headers", "applicability": "Inspects the response header; does not inspect per-element policy or data flows."}],
    "header.permissions_policy": [{"framework": "OWASP Secure Headers Project", "version": "current guidance", "control": "Permissions-Policy", "source_url": "https://owasp.org/projects/secure-headers-project", "applicability": "Optional policy; expected directives depend on site features."}],
    "header.cookie_security": [{"framework": "OWASP ASVS", "version": "5.0.0", "control": "V3.3.1 Secure; V3.3.2 SameSite; V3.3.4 HttpOnly", "source_url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0/03-web-frontend-security/03-cookie-setup", "applicability": "Only attributes visible on this response are checked; HttpOnly/SameSite expectations depend on cookie purpose. No session behavior is tested."}],
    "tls.protocol_version": [{"framework": "OWASP TLS Cheat Sheet", "version": "current guidance", "control": "Strong protocol recommendations", "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html", "applicability": "Reports only the protocol negotiated for one connection, not all enabled server protocols."}],
    "tls.cipher_strength": [{"framework": "OWASP TLS Cheat Sheet", "version": "current guidance", "control": "Strong cipher recommendations", "source_url": "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html", "applicability": "Bounded negotiated-cipher check; not a complete cipher inventory."}],
}


def annotate_findings(findings) -> list[dict]:
    """Return finding dictionaries with separated confidence, risk and mappings.

    Per-finding score is a prioritization aid. Overall risk uses maximum score
    per related check family to avoid summing correlated header/TLS observations.
    """
    output = []
    for finding in findings:
        row = finding.to_dict() if hasattr(finding, "to_dict") else dict(finding)
        status = str(row.get("status", "inconclusive"))
        severity = str(row.get("severity", "informational")).lower()
        evidence = str(row.get("evidence", ""))
        confidence = 0.95 if evidence and status in {"pass", "finding", "warning", "fail"} else 0.55 if evidence else 0.25
        exposure = 1.0
        check_id = str(row.get("check_id", ""))
        if check_id == "https.reachable" and status == "pass":
            exposure = 0.25
        impact = IMPACT_BY_CHECK.get(check_id, 0.6)
        base = SEVERITY_WEIGHT.get(severity, 5)
        score = round(min(100, base * confidence * exposure * impact)) if status in UNRESOLVED else 0
        rationale = (f"{severity.title()} severity weight {base}/100 × evidence confidence {confidence:.2f} × "
                     f"exposure factor {exposure:.2f} × impact factor {impact:.2f}; capped at 100. "
                     "This prioritization is advisory and does not establish exploitability.")
        row["risk"] = {"score": score, "confidence": confidence, "exposure_factor": exposure,
                       "impact_factor": impact, "rationale": rationale,
                       "confidence_basis": "direct response evidence" if confidence >= 0.9 else "limited or incomplete evidence"}
        row["standards"] = STANDARDS.get(check_id, [])
        output.append(row)
    return output


def aggregate_risk(findings: list[dict]) -> dict:
    families = defaultdict(list)
    for row in findings:
        check_id = str(row.get("check_id", "other"))
        family = check_id.split(".", 1)[0]
        families[family].append(int((row.get("risk") or {}).get("score", 0)))
    score = min(100, sum(max(values, default=0) for values in families.values()))
    return {"score": score, "method": "sum of maximum unresolved finding score per check family, capped at 100",
            "families_counted": len(families), "advisory": True}
