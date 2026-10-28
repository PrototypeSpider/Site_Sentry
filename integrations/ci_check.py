"""Bounded passive scan command for an explicitly authorized CI job."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from config import _parse_domains
from scanner.engine import Scanner


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
UNRESOLVED = {"finding", "warning", "fail", "error", "inconclusive"}


def failure_reason(report: dict, *, fail_on: str, min_risk: int) -> str | None:
    if report.get("scan_status") != "completed":
        return "scan_incomplete"
    for finding in report.get("findings", []):
        if finding.get("status") not in UNRESOLVED:
            continue
        severity = str(finding.get("severity", "informational")).lower()
        score = int((finding.get("risk") or {}).get("score", 0))
        severity_failed = fail_on != "none" and SEVERITY_ORDER.get(severity, 99) <= SEVERITY_ORDER[fail_on]
        risk_failed = min_risk > 0 and score >= min_risk
        if severity_failed or risk_failed:
            return "configured_threshold_exceeded"
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run SiteSentry passive checks for an authorized deployment target.")
    parser.add_argument("--url", required=True, help="HTTP(S) URL on a standard port")
    parser.add_argument("--profile", choices=("advanced",), default="advanced",
                        help="Scan profile is fixed to Advanced for the CLI tool.")
    parser.add_argument("--authorized", action="store_true", help="Confirm you are authorized to assess this target")
    parser.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "low"), default="high")
    parser.add_argument("--min-risk", type=int, default=0, help="Fail when any unresolved finding risk score meets this value (1-100)")
    parser.add_argument("--output", help="Optional JSON report path; report is also written to stdout")
    args = parser.parse_args(argv)
    if not args.authorized:
        parser.error("--authorized is required; only scan systems you are permitted to assess")
    if not 0 <= args.min_risk <= 100:
        parser.error("--min-risk must be between 0 and 100")

    allowed = _parse_domains(os.getenv("SITESENTRY_ALLOWED_DOMAINS", ""))
    scanner = Scanner(timeout=(float(os.getenv("SITESENTRY_CONNECT_TIMEOUT", "3.05")),
                               float(os.getenv("SITESENTRY_READ_TIMEOUT", "7"))),
                      allowed_domains=set(allowed) or None)
    result = scanner.scan(args.url, profile=args.profile).to_dict()
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        destination = Path(args.output).expanduser().resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 2 if result.get("scan_status") != "completed" else 1 if failure_reason(result, fail_on=args.fail_on, min_risk=args.min_risk) else 0


if __name__ == "__main__":
    sys.exit(main())
