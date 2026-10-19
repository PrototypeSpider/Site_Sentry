"""Human-readable XAI report generated only from a normalized scan result."""

from __future__ import annotations

import html
import re
from collections import Counter
from urllib.parse import urlsplit


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
URL_PATTERN = re.compile(r"https?://[^\s\]\[,'\"<>]+", re.IGNORECASE)


def _link_label(match: re.Match) -> str:
    """Hide URL paths and query parameters; they may contain login/API links."""
    try:
        hostname = urlsplit(match.group(0).rstrip(".,;)")).hostname
    except ValueError:
        hostname = None
    return hostname or "external destination"


def _text(value: object) -> str:
    """Keep untrusted evidence on one safe Markdown line."""
    normalized = " ".join(str(value or "—").split())
    normalized = URL_PATTERN.sub(_link_label, normalized)
    return html.escape(normalized, quote=False).replace("`", "&#96;")


def _human_evidence(item: dict) -> str:
    """Turn redirect-chain serialization into a short plain-language sentence."""
    check_id = item.get("check_id")
    evidence = str(item.get("evidence") or "")
    if check_id == "http.https_redirect":
        initial = re.search(r"Initial scheme=([a-zA-Z]+)", evidence)
        final = re.search(r"final scheme=([a-zA-Z]+)", evidence)
        destinations = URL_PATTERN.findall(evidence)
        start_scheme = initial.group(1).upper() if initial else "unknown"
        end_scheme = final.group(1).upper() if final else "unknown"
        suffix = f" It followed {len(destinations)} redirect(s)." if destinations else ""
        if start_scheme == "HTTPS":
            return "This check applies to HTTP requests, but the scan started with HTTPS. HTTP-to-HTTPS redirect behavior was not assessed. Full redirect links are hidden."
        return f"The request started over {start_scheme} and ended over {end_scheme}.{suffix} Full redirect links are hidden."
    if check_id == "http.redirect_chain":
        count = re.search(r"Safely followed (\d+) redirect", evidence)
        destinations = URL_PATTERN.findall(evidence)
        final_host = _link_label(re.match(r".*", destinations[-1])) if destinations else None
        destination_text = f" The final site was {final_host}." if final_host else ""
        followed = f"{count.group(1)}" if count else "The site"
        prefix = f"SiteSentry safely followed {followed} redirect(s)." if count else "SiteSentry safely followed the redirect chain."
        return prefix + destination_text + " Full URL paths and query values are hidden."
    return evidence


def generate_xai_report(scan: dict) -> dict:
    findings = scan.get("findings") or []
    findings = sorted(findings, key=lambda item: (
        SEVERITY_ORDER.get(str(item.get("severity", "informational")).lower(), 5),
        str(item.get("check", item.get("check_id", ""))).lower(),
    ))
    summary = scan.get("summary") or {}
    metrics = scan.get("metrics") or {}
    checks_passed = metrics.get("checks_passed", summary.get("pass", 0))
    review_count = metrics.get("findings_to_review", sum(
        item.get("status") in {"finding", "warning", "fail", "error", "inconclusive"} for item in findings
    ))
    high_critical = metrics.get("high_critical_findings", sum(
        item.get("severity") in {"high", "critical"} and item.get("status") != "pass" for item in findings
    ))
    tls_verified = metrics.get("tls_verified")
    duration = metrics.get("scan_duration_seconds")
    scan_state = scan.get("scan_status", scan.get("status", "unknown"))
    profile = (scan.get("metadata") or {}).get("scan_profile", scan.get("profile", "standard"))

    if scan_state == "error":
        overview = "The scan failed before it could complete. Treat uncollected checks as unknown, not as passes."
    elif scan_state == "partial":
        overview = "The scan completed partially. Review the collected evidence and do not treat uncollected checks as passes."
    elif review_count:
        overview = f"The scan completed and recorded {review_count} item(s) that need review. This is configuration evidence, not proof of an exploitable vulnerability."
    else:
        overview = "The scan completed without recorded review items in the selected profile. A pass covers only the checks that ran."

    lines = [
        "# Explainable scan report",
        "",
        f"**Target:** {_text(scan.get('target'))}  ",
        f"**Scan ID:** {_text(scan.get('scan_id'))}  ",
        f"**Profile:** {_text(profile)}  ",
        f"**Scan state:** {_text(scan_state)}  ",
        f"**Completed:** {_text(scan.get('completed_at'))}",
        "",
        "## Human-readable summary",
        "",
        _text(overview),
        "",
        f"- Checks passed: **{checks_passed}**",
        f"- Findings to review: **{review_count}**",
        f"- High/critical findings: **{high_critical}**",
        f"- TLS certificate verification: **{'verified' if tls_verified is True else 'not verified' if tls_verified is False else 'not assessed'}**",
        f"- Scan duration: **{f'{duration:.1f} seconds' if isinstance(duration, (int, float)) else 'not available'}**",
        "",
        "## Findings and rationale",
        "",
    ]

    if not findings:
        lines.append("No check-level findings were recorded for this scan.")
    for item in findings:
        check = item.get("check", item.get("check_id", "Security check"))
        lines.extend([
            f"### {_text(check)}",
            "",
            f"**Severity:** {_text(item.get('severity', 'informational'))} · **Status:** {_text(item.get('status', 'unknown'))}",
            "",
            f"**What we observed:** {_text(_human_evidence(item))}",
            "",
            f"**Why this matters:** {_text(item.get('explanation'))}",
            "",
            f"**What to do next:** {_text(item.get('recommendation'))}",
            "",
        ])
        xai = item.get("xai") or {}
        contributions = xai.get("feature_contributions") or []
        if xai.get("status") == "available" and contributions:
            lines.append("**Model feature contributions (advisory):**")
            for contribution in sorted(contributions, key=lambda row: abs(float(row.get("contribution", 0))), reverse=True)[:3]:
                value = float(contribution.get("contribution", 0))
                direction = "increases" if value > 0 else "decreases" if value < 0 else "does not change"
                lines.append(f"- `{_text(contribution.get('feature'))}` {direction} the model output (SHAP {value:+.4f}).")
            lines.extend(["", "These values explain model behavior relative to its reference data; they are not causal evidence.", ""])

    passed = [item for item in findings if item.get("status") == "pass"]
    if passed:
        lines.extend(["## Checks that passed", ""])
        lines.extend(f"- {_text(item.get('check', item.get('check_id', 'Check')))}" for item in passed)
        lines.append("")

    not_assessed = [item for item in findings if item.get("status") in {"not_assessed", "inconclusive", "error"}]
    if not_assessed:
        lines.extend(["## Checks not fully assessed", ""])
        lines.extend(f"- **{_text(item.get('check', item.get('check_id', 'Check')))}** ({_text(item.get('status'))}): {_text(item.get('evidence'))}" for item in not_assessed)
        lines.append("")

    limitations = scan.get("limitations") or []
    lines.extend([
        "## How to read this report",
        "",
        "The explanations above are derived from SiteSentry's recorded rule rationale, evidence, and remediation guidance. They describe observed configuration and do not establish exploitability or certify that the website is secure.",
    ])
    if limitations:
        lines.extend(["", "### Scan limitations", ""])
        lines.extend(f"- {_text(item)}" for item in limitations)
    lines.append("")
    return {
        "template_version": "sitesentry-xai-report-1.0",
        "scan_id": scan.get("scan_id"),
        "title": "Explainable scan report",
        "markdown": "\n".join(lines),
        "finding_count": len(findings),
        "status_counts": dict(Counter(item.get("status", "unknown") for item in findings)),
    }
