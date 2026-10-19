"""Bounded, passive detection logic inspired by common security scanners.

These detectors operate only on the response and TLS handshake already collected
by SafeTransport. They do not make extra requests, probe ports, crawl paths, or
claim that a fingerprint proves a vulnerability.
"""

from __future__ import annotations

import re

from .models import Finding
from .transport import HttpObservation


_PRODUCT_HEADER = re.compile(r"\b(server|x-powered-by|x-aspnet-version|x-generator|via)\b", re.I)
_VERSION = re.compile(r"(?:\b\d{1,4}\.\d+(?:\.\d+){0,2}(?:[-+._][\w.-]+)?\b)")
_WAF_HEADERS = {
    "cf-ray": "Cloudflare",
    "cf-cache-status": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "x-sucuri-cache": "Sucuri",
    "x-akamai-transformed": "Akamai",
    "x-cdn": "CDN/WAF indicator",
    "x-iinfo": "Imperva/Incapsula",
    "x-waf-event-info": "WAF indicator",
}


def evaluate_passive_fingerprints(observation: HttpObservation) -> list[Finding]:
    """Apply passive banner, WAF-indicator, and curated evidence-template logic."""
    headers = {str(name).lower(): str(value)[:512] for name, value in observation.headers.items()}
    findings: list[Finding] = []

    # WhatWeb/Nmap-style banner fingerprinting: identify technologies solely
    # from the HTTP response that was already collected.
    product_headers = {key: value for key, value in headers.items() if _PRODUCT_HEADER.fullmatch(key)}
    if product_headers:
        summary = ", ".join(f"{key}: {_safe_banner(value)}" for key, value in sorted(product_headers.items()))[:800]
        findings.append(Finding(
            "fingerprint.http_technology", "HTTP technology indicators", "inconclusive", "informational",
            f"Passive response banners observed: {summary}.",
            "HTTP banners can suggest server-side technologies, but they may be hidden, changed, or intentionally inaccurate. Identification does not establish a vulnerability.",
            "Review whether detailed technology banners are needed; keep server and framework components patched.",
            source="Passive WhatWeb/Nmap-inspired response fingerprint",
        ))
    else:
        findings.append(Finding(
            "fingerprint.http_technology", "HTTP technology indicators", "inconclusive", "informational",
            "No recognized technology-identification headers were present in the inspected response.",
            "A missing banner does not mean the server technology is unknown or secure; this passive check does not probe services or inspect page content.",
            "Treat technology identification as unavailable from this response.",
            source="Passive WhatWeb/Nmap-inspired response fingerprint",
        ))

    # Nmap-style service inference is deliberately restricted to the single
    # HTTP(S) service already contacted; there is no port discovery.
    tls = observation.tls or {}
    service_parts = []
    if observation.final_url.lower().startswith("https://"):
        service_parts.append(f"HTTPS; negotiated {tls.get('version') or 'TLS version unavailable'}")
    else:
        service_parts.append("HTTP")
    if headers.get("server"):
        service_parts.append(f"server banner present ({_safe_banner(headers['server'])})")
    findings.append(Finding(
        "fingerprint.web_service", "Observed web service", "inconclusive", "informational",
        "; ".join(service_parts) + ".",
        "This is service identification from the existing web response and handshake only. It is not a port scan or a complete service/version inventory.",
        "Use an explicitly authorized network assessment when a full service inventory is required.",
        source="Passive Nmap-inspired service identification",
    ))

    # wafw00f-style indicators are heuristic. Their absence cannot rule out a WAF.
    wafs = sorted({vendor for key, vendor in _WAF_HEADERS.items() if key in headers})
    findings.append(Finding(
        "fingerprint.waf_indicator", "Web application firewall indicators", "inconclusive", "informational",
        ("Response headers contain indicators associated with " + ", ".join(wafs) + ".") if wafs
        else "No recognized WAF-related response headers were observed.",
        "Header signatures are heuristic and can be added, removed, or spoofed. A detected indicator does not prove effective protection, and no indicator does not prove a WAF is absent.",
        "Verify WAF deployment and policy in the hosting configuration; do not treat this passive indicator as a security control test.",
        source="Passive wafw00f-inspired header signatures",
    ))

    # Nikto/Nuclei-inspired curated templates evaluate existing evidence only.
    # Keep this as one finding so it cannot inflate counts by duplicating the
    # detailed HSTS/CSP/clickjacking findings already emitted by the rule engine.
    matched = _passive_template_matches(headers, observation)
    findings.append(Finding(
        "templates.passive_web_review", "Curated passive web configuration templates",
        "warning" if matched else "inconclusive",
        "low" if matched else "informational",
        ("Matched evidence-only review templates: " + "; ".join(matched) + ".") if matched
        else "No configured evidence-only templates matched the collected response.",
        "These reviewed templates inspect only the captured headers/status. They do not request known paths, test payloads, or prove exploitability; detailed check findings remain authoritative.",
        "Review the linked detailed header findings and confirm configuration against the application’s intended behavior.",
        source="Curated passive Nikto/Nuclei-inspired evidence templates",
    ))
    return findings


def _passive_template_matches(headers: dict[str, str], observation: HttpObservation) -> list[str]:
    matches: list[str] = []
    banners = " ".join(value for key, value in headers.items() if _PRODUCT_HEADER.fullmatch(key))
    if _VERSION.search(banners):
        matches.append("server/framework version disclosed in a response banner")
    if headers.get("x-content-type-options", "").strip().lower() not in {"", "nosniff"}:
        matches.append("X-Content-Type-Options is present with an unexpected value")
    if headers.get("x-frame-options", "").strip().lower() not in {"", "deny", "sameorigin"}:
        matches.append("X-Frame-Options contains an unrecognized value")
    if observation.status_code >= 500:
        matches.append(f"server returned HTTP {observation.status_code} for the inspected request")
    return matches


def _safe_banner(value: str) -> str:
    """Bound banner text and remove control characters before storing evidence."""
    return re.sub(r"[\x00-\x1f\x7f]", " ", value).strip()[:180] or "(empty)"
