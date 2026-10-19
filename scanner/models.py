"""Stable, JSON-friendly models for scanner evidence and results."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

Status = Literal["pass", "finding", "warning", "fail", "error", "not_assessed", "inconclusive"]
Severity = Literal["critical", "high", "medium", "low", "informational"]


@dataclass(slots=True)
class Finding:
    check_id: str
    check: str
    status: Status
    severity: Severity
    evidence: str
    explanation: str
    recommendation: str
    observed_at: str = field(default_factory=lambda: utc_now())
    rule_version: str = "1.0"
    source: str = "SiteSentry passive HTTP/TLS scanner"
    ml_assessment: dict[str, Any] = field(default_factory=lambda: {"status": "not_configured", "model": None, "prediction": None, "confidence": None})
    xai: dict[str, Any] = field(default_factory=dict)
    ai_explanation: dict[str, Any] = field(default_factory=lambda: {"status": "not_configured", "provider": None, "content": None})
    risk: dict[str, Any] = field(default_factory=dict)
    standards: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanResult:
    target: str
    scan_status: Literal["completed", "partial", "error"]
    findings: list[Finding]
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=lambda: utc_now())
    completed_at: str = field(default_factory=lambda: utc_now())
    scanner_version: str = "0.1.0"
    modules_executed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    status: Literal["queued", "running", "completed", "partial", "error", "cancelled"] | None = None

    @property
    def summary(self) -> dict[str, int]:
        return {status: sum(f.status == status for f in self.findings) for status in ("pass", "finding", "warning", "fail", "error", "not_assessed", "inconclusive")}

    @property
    def metrics(self) -> dict[str, Any]:
        try:
            duration = (datetime.fromisoformat(self.completed_at) - datetime.fromisoformat(self.started_at)).total_seconds()
        except (TypeError, ValueError):
            duration = None
        tls = self.metadata.get("tls")
        return {
            "checks_passed": sum(item.status == "pass" for item in self.findings),
            "findings_to_review": sum(item.status in {"finding", "warning", "fail", "error", "inconclusive"} for item in self.findings),
            "high_critical_findings": sum(item.severity in {"critical", "high"} and item.status != "pass" for item in self.findings),
            "tls_verified": tls.get("verified") if isinstance(tls, dict) else None,
            "scan_duration_seconds": max(0.0, duration) if duration is not None else None,
        }

    def to_dict(self) -> dict[str, Any]:
        from .risk import aggregate_risk, annotate_findings
        findings = annotate_findings(self.findings)
        return {
            "schema_version": "1.0",
            "scan_id": self.scan_id,
            "target": self.target,
            "scan_status": self.scan_status,
            "status": self.status or self.scan_status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "scanner_version": self.scanner_version,
            "modules_executed": self.modules_executed,
            "summary": self.summary,
            "metrics": self.metrics,
            "findings": findings,
            "risk_summary": aggregate_risk(findings),
            "errors": self.errors,
            "limitations": self.limitations,
            "metadata": self.metadata,
        }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
