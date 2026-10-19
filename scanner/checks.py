"""Deterministic HTTP header and TLS rules with explicit limitations."""

from __future__ import annotations

from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import re

from .models import Finding
from .transport import HttpObservation


def evaluate_observation(observation: HttpObservation) -> list[Finding]:
    headers = {name.lower(): value for name, value in observation.headers.items()}
    findings: list[Finding] = []
    https = observation.final_url.lower().startswith("https://")
    findings.append(Finding(
        "https.reachable", "HTTPS reachability", "pass" if https else "warning", "informational" if https else "medium",
        f"Final response URL used {'HTTPS' if https else 'HTTP'}; status code {observation.status_code}.",
        "HTTPS protects the connection in transit when certificate validation succeeds. This result says nothing about the site's overall security.",
        "Serve the site over HTTPS and redirect HTTP traffic to HTTPS where appropriate.",
    ))
    if https:
        tls = observation.tls or {}
        verified = tls.get("verified") is True
        findings.append(Finding(
            "tls.certificate_validation", "TLS certificate validation", "pass" if verified else "error", "informational" if verified else "high",
            "The TLS connection completed with standard certificate-chain and hostname verification." if verified else "TLS verification could not be confirmed.",
            "A verified TLS handshake establishes that the certificate is trusted for this host at connection time; it does not prove all TLS settings are strong.",
            "Use a publicly trusted, current certificate that matches the hostname.",
        ))
        findings.append(_certificate_expiry(tls))
    else:
        findings.append(Finding("tls.certificate_validation", "TLS certificate validation", "not_assessed", "informational", "The final response did not use HTTPS.", "No TLS certificate was presented for the final response.", "Enable HTTPS before assessing certificate configuration."))
        findings.append(Finding("tls.certificate_expiry", "TLS certificate expiry", "not_assessed", "informational", "No HTTPS certificate was observed.", "Certificate validity dates are only assessed for HTTPS responses.", "Enable HTTPS and repeat the assessment."))

    rules = [
        ("header.hsts", "Strict-Transport-Security", "strict-transport-security", "medium", "Helps browsers enforce HTTPS on future visits after the policy is received over HTTPS.", "Configure an appropriate max-age; add includeSubDomains or preload only after reviewing their scope."),
        ("header.csp", "Content-Security-Policy", "content-security-policy", "medium", "A suitable CSP can restrict the sources from which a browser loads page resources.", "Develop and test a policy that matches the site's resource requirements; consider report-only rollout."),
        ("header.x_content_type_options", "X-Content-Type-Options", "x-content-type-options", "low", "The nosniff directive helps browsers respect declared MIME types.", "Where appropriate, send X-Content-Type-Options: nosniff."),
        ("header.referrer_policy", "Referrer-Policy", "referrer-policy", "low", "Controls how much referrer information browsers send with navigation requests.", "Choose a policy appropriate for the site's privacy and compatibility needs."),
        ("header.permissions_policy", "Permissions-Policy", "permissions-policy", "informational", "Can limit access to selected browser features.", "Review whether a Permissions-Policy is appropriate for features used by the site."),
    ]
    for check_id, label, key, severity, purpose, recommendation in rules:
        value = headers.get(key)
        status = "pass" if value else "finding"
        evidence = f"Observed: {value[:300]}" if value else "Header not observed in the inspected response."
        if key == "strict-transport-security" and value and not https:
            status = "finding"
            evidence += " HSTS received over HTTP is ignored by browsers."
        if key == "strict-transport-security" and value:
            directives = _parse_directives(value)
            try:
                max_age = int(directives.get("max-age", "-1"))
            except ValueError:
                max_age = -1
            if max_age < 0:
                status = "finding"
                evidence += " Invalid or missing max-age directive."
            elif max_age < 31_536_000:
                status = "warning"
                evidence += f" max-age is {max_age} seconds, below the scanner's one-year review threshold."
            if max_age >= 0:
                evidence += (" includeSubDomains is enabled." if "includesubdomains" in directives else
                             " includeSubDomains is absent; confirm subdomain policy requirements before enabling it.")
                if "preload" in directives:
                    evidence += " preload is requested; verify preload eligibility and all subdomains before submission."
        elif key == "x-content-type-options" and value and value.strip().lower() != "nosniff":
            status = "finding"
            evidence += " Expected nosniff directive was not observed."
        elif key == "referrer-policy" and value and value.strip().lower() not in {"no-referrer", "no-referrer-when-downgrade", "same-origin", "origin", "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url"}:
            status = "finding"
            evidence += " Value is not a recognized Referrer-Policy token."
        findings.append(Finding(check_id, label, status, "informational" if status == "pass" else severity, evidence,
                                f"{purpose} Absence alone does not establish an exploitable vulnerability.", recommendation))

    csp_value = headers.get("content-security-policy", "")
    csp = csp_value.lower()
    if csp_value:
        directives = _parse_directives(csp_value)
        default_sources = directives.get("default-src", "")
        script_sources = directives.get("script-src", default_sources)
        policy_issues = []
        if not default_sources:
            policy_issues.append("default-src is absent; resource-type defaults may be broader than intended")
        for directive_name, directive_value in directives.items():
            if "*" in directive_value:
                policy_issues.append(f"{directive_name} contains a wildcard source")
        if "'unsafe-eval'" in script_sources:
            policy_issues.append("script sources allow unsafe-eval")
        has_nonce_or_hash = any(token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for token in script_sources.split())
        if "'unsafe-inline'" in script_sources and not has_nonce_or_hash:
            policy_issues.append("script sources allow unsafe-inline without a nonce or hash")
        if policy_issues:
            csp_finding = next((item for item in findings if item.check_id == "header.csp"), None)
            if csp_finding:
                csp_finding.status = "warning"
                csp_finding.severity = "medium"
                csp_finding.evidence += " Policy review: " + "; ".join(policy_issues) + "."
                csp_finding.explanation += " The observed policy also contains directives that merit review."
                csp_finding.recommendation = "Review broad sources and unsafe script directives; test a restrictive policy in report-only mode before enforcement."
    xfo = headers.get("x-frame-options", "").lower()
    xfo_valid = xfo in {"deny", "sameorigin"}
    framing_block = "frame-ancestors" in csp or xfo_valid
    findings.append(Finding(
        "header.clickjacking_protection", "Clickjacking protection", "pass" if framing_block else "finding",
        "informational" if framing_block else "low",
        "CSP frame-ancestors directive observed." if "frame-ancestors" in csp else (f"Effective X-Frame-Options observed: {xfo}" if xfo_valid else (f"Unrecognized X-Frame-Options value: {xfo}" if xfo else "Neither CSP frame-ancestors nor an effective X-Frame-Options value was observed.")),
        "Framing restrictions can reduce clickjacking risk; whether framing is unsafe depends on the application and its flows.",
        "Where embedding is not required, configure CSP frame-ancestors; use X-Frame-Options as a compatibility fallback.",
    ))
    findings.append(_cookie_security(headers.get("set-cookie"), https))
    return findings


def _cookie_security(value: str | None, https: bool) -> Finding:
    if not value:
        return Finding("header.cookie_security", "Cookie security attributes", "not_assessed", "informational",
            "No Set-Cookie header was visible in the inspected response.",
            "Cookies may be set on other paths or only after application interaction; this response alone is not a complete cookie inventory.",
            "Review session and sensitive cookies on authenticated application flows using an authorized assessment.")
    # Never include cookie names or values in evidence. Multiple Set-Cookie
    # headers may have been joined by the HTTP layer; split conservatively.
    segments = [part.strip() for part in re.split(r",\s*(?=[!#$%&'*+.^_`|~0-9A-Za-z-]+=)", value) if part.strip()]
    missing_secure = missing_http_only = missing_samesite = 0
    none_without_secure = 0
    for segment in segments:
        attributes = {piece.strip().partition("=")[0].lower(): piece.strip().partition("=")[2].strip().strip('"').lower()
                      for piece in segment.split(";")[1:] if piece.strip()}
        if "secure" not in attributes:
            missing_secure += 1
        if "httponly" not in attributes:
            missing_http_only += 1
        if "samesite" not in attributes:
            missing_samesite += 1
        if attributes.get("samesite") == "none" and "secure" not in attributes:
            none_without_secure += 1
    issues = []
    if missing_secure: issues.append(f"Secure missing on {missing_secure} observed cookie(s)")
    if missing_http_only: issues.append(f"HttpOnly missing on {missing_http_only} observed cookie(s)")
    if missing_samesite: issues.append(f"SameSite missing on {missing_samesite} observed cookie(s)")
    if none_without_secure: issues.append(f"SameSite=None without Secure on {none_without_secure} observed cookie(s)")
    status = "warning" if issues else "pass"
    return Finding("header.cookie_security", "Cookie security attributes", status,
        "medium" if issues else "informational",
        f"Inspected {len(segments)} Set-Cookie value(s); " + ("; ".join(issues) if issues else "Secure, HttpOnly, and SameSite attributes were observed."),
        "Cookie flags reduce browser-side exposure and cross-site request risks, but correct attributes depend on cookie purpose and application behavior. Cookie values and names are intentionally omitted.",
        "Set Secure for HTTPS cookies, HttpOnly for cookies not read by client scripts, and an appropriate SameSite policy; keep SameSite=None only with Secure.")


def evaluate_advanced_observation(observation: HttpObservation) -> list[Finding]:
    """Add passive TLS/CSP checks that require deeper interpretation."""
    findings: list[Finding] = []
    tls = observation.tls or {}
    version = tls.get("version")
    if not observation.final_url.lower().startswith("https://"):
        findings.append(Finding("tls.protocol_version", "TLS protocol version", "not_assessed", "informational",
            "The final response did not use HTTPS.", "No TLS protocol was negotiated for the final response.",
            "Enable HTTPS before reviewing negotiated TLS versions."))
        findings.append(Finding("tls.cipher_strength", "TLS cipher suite", "not_assessed", "informational",
            "No TLS cipher suite was observed.", "Cipher review requires an HTTPS connection.",
            "Enable HTTPS before reviewing negotiated cipher suites."))
    elif version in {"TLSv1.2", "TLSv1.3"}:
        findings.append(Finding("tls.protocol_version", "TLS protocol version", "pass", "informational",
            f"Negotiated protocol: {version}.", "TLS 1.2 or 1.3 was negotiated. This check evaluates only the protocol used for this connection.",
            "Keep TLS 1.2 and 1.3 enabled and disable older protocol versions."))
    elif version in {"TLSv1", "TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"}:
        findings.append(Finding("tls.protocol_version", "TLS protocol version", "fail", "high",
            f"Negotiated outdated protocol: {version}.", "Older TLS/SSL protocol versions have known cryptographic weaknesses and should not be negotiated.",
            "Disable TLS versions earlier than 1.2 and verify compatibility."))
    else:
        findings.append(Finding("tls.protocol_version", "TLS protocol version", "inconclusive", "informational",
            f"Negotiated version could not be assessed: {version!r}.", "The scanner did not recognize the negotiated protocol value.",
            "Review the protocol with a maintained TLS configuration tool."))

    cipher_details = tls.get("cipher")
    cipher_name = cipher_details[0] if isinstance(cipher_details, (tuple, list)) and cipher_details else None
    if not isinstance(cipher_name, str):
        cipher_status, cipher_severity = "inconclusive", "informational"
        cipher_evidence = "Negotiated cipher suite details were unavailable."
    else:
        weak_markers = ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5", "RC2")
        weak = any(marker in cipher_name.upper() for marker in weak_markers)
        cipher_status, cipher_severity = ("fail", "high") if weak else ("pass", "informational")
        cipher_evidence = f"Negotiated cipher suite: {cipher_name}. " + ("Matched a known legacy/insecure cipher marker." if weak else "No known legacy/insecure marker matched.")
    findings.append(Finding("tls.cipher_strength", "TLS cipher suite", cipher_status, cipher_severity,
        cipher_evidence, "This bounded check flags a small set of widely recognized legacy cipher names; a pass is not a complete cryptographic audit.",
        "Prefer modern AEAD cipher suites and verify the full server cipher configuration with a maintained TLS analysis tool."))

    headers = {name.lower(): value for name, value in observation.headers.items()}
    csp = headers.get("content-security-policy", "").lower()
    if not csp:
        csp_status, csp_severity, csp_evidence = "not_assessed", "informational", "No Content-Security-Policy was observed; directive quality cannot be assessed."
    else:
        directives = _parse_directives(csp)
        script_sources = directives.get("script-src", directives.get("default-src", ""))
        has_nonce_or_hash = any(token.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for token in script_sources.split())
        unsafe_eval = "'unsafe-eval'" in script_sources
        unsafe_inline = "'unsafe-inline'" in script_sources and not has_nonce_or_hash
        issues = []
        if not script_sources:
            issues.append("neither script-src nor default-src was observed")
        if unsafe_eval:
            issues.append("unsafe-eval is enabled")
        if unsafe_inline:
            issues.append("unsafe-inline is enabled without a nonce/hash source")
        csp_status, csp_severity = ("warning", "medium") if issues else ("pass", "informational")
        csp_evidence = "; ".join(issues) if issues else "No unsafe-inline/eval directive was observed (or inline use is paired with a nonce/hash source)."
    findings.append(Finding("header.csp_directives", "CSP directive quality", csp_status, csp_severity,
        csp_evidence, "This is a bounded review of inline/eval directives and does not validate every CSP source or application flow.",
        "Prefer nonce/hash-based scripts, remove unsafe-eval where possible, and test a restrictive policy in report-only mode first."))
    return findings


def _parse_directives(value: str) -> dict[str, str]:
    directives = {}
    for part in value.split(";"):
        token = part.strip()
        if "=" in token:
            name, _, directive_value = token.partition("=")
        else:
            name, _, directive_value = token.partition(" ")
        if name:
            directives[name.lower()] = directive_value.strip()
    return directives


def _certificate_expiry(tls: dict[str, object]) -> Finding:
    not_after = tls.get("not_after")
    if not isinstance(not_after, str):
        return Finding("tls.certificate_expiry", "TLS certificate expiry", "error", "informational", "Certificate validity details were unavailable from the TLS connection.", "The certificate was verified, but its expiry date could not be extracted for this report.", "Inspect the certificate with a trusted TLS diagnostic if expiry monitoring is required.")
    try:
        expires = parsedate_to_datetime(not_after).astimezone(timezone.utc)
        days = (expires - datetime.now(timezone.utc)).days
    except (TypeError, ValueError, OverflowError):
        return Finding("tls.certificate_expiry", "TLS certificate expiry", "error", "informational", "Certificate expiry date could not be parsed.", "The expiry rule could not assess the certificate date.", "Inspect the certificate with a trusted TLS diagnostic.")
    status = "fail" if days < 0 else "warning" if days <= 30 else "pass"
    severity = "high" if days < 0 else "medium" if days <= 30 else "informational"
    evidence = f"Certificate notAfter={expires.isoformat()} ({days} days remaining)."
    return Finding("tls.certificate_expiry", "TLS certificate expiry", status, severity, evidence,
                   "An expired certificate causes standard browsers to reject the TLS connection; near-expiry certificates need renewal planning.",
                   "Renew the certificate before it expires and ensure renewal is automated and monitored.")
