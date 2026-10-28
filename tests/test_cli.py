from __future__ import annotations

from types import SimpleNamespace

from typer.testing import CliRunner

from sitesentry import cli


REPORT = {
    "scan_id": "cli-test-scan",
    "target": "https://example.test/",
    "scan_status": "completed",
    "started_at": "2026-10-28T10:00:00+00:00",
    "completed_at": "2026-10-28T10:00:01+00:00",
    "profile": "advanced",
    "metadata": {"scan_profile": "advanced"},
    "summary": {"pass": 1, "finding": 0, "warning": 0, "fail": 0, "error": 0, "inconclusive": 0},
    "metrics": {"checks_passed": 1, "findings_to_review": 0, "high_critical_findings": 0,
                "tls_verified": True, "scan_duration_seconds": 1.0},
    "findings": [{"check_id": "https.reachable", "check": "HTTPS reachability", "status": "pass",
                   "severity": "informational", "evidence": "HTTPS response observed.",
                   "recommendation": "Keep HTTPS enabled."}],
    "limitations": [],
    "errors": [],
}


def _configure_test_scan(monkeypatch, tmp_path):
    monkeypatch.setenv("SITESENTRY_DATABASE", str(tmp_path / "history.sqlite3"))
    monkeypatch.setenv("SITESENTRY_REPORT_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("SITESENTRY_ALLOWED_DOMAINS", "example.test")
    monkeypatch.setattr(cli, "validate_target", lambda url, allowed_domains=None: SimpleNamespace(url=url))

    class FakeScanner:
        def __init__(self, *, timeout, allowed_domains):
            assert timeout == (3.05, 7.0)
            assert allowed_domains == {"example.test"}

        def scan(self, url, *, profile):
            assert profile == "advanced"
            return SimpleNamespace(to_dict=lambda: dict(REPORT))

    monkeypatch.setattr("scanner.engine.Scanner", FakeScanner)


def test_cli_scan_is_advanced_only_persists_history_and_emits_json(monkeypatch, tmp_path):
    _configure_test_scan(monkeypatch, tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli.app, ["scan", "https://example.test", "--authorized", "--format", "json"])

    assert result.exit_code == 0
    assert '"scan_status": "completed"' in result.stdout
    assert '"scan_profile": "advanced"' in result.stdout
    assert (tmp_path / "reports" / "cli-test-scan.json").is_file()
    history = runner.invoke(cli.app, ["history"])
    assert history.exit_code == 0
    assert "ADVANCED" in history.stdout
    assert "cli-test-scan" in history.stdout


def test_cli_requires_authorization_and_rejects_profile_switch(monkeypatch, tmp_path):
    _configure_test_scan(monkeypatch, tmp_path)
    runner = CliRunner()

    unauthorized = runner.invoke(cli.app, ["scan", "https://example.test"])
    assert unauthorized.exit_code == 3
    assert "--authorized" in unauthorized.stderr

    profile_switch = runner.invoke(cli.app, ["scan", "https://example.test", "--profile", "quick", "--authorized"])
    assert profile_switch.exit_code == 2
    assert "--profile" in profile_switch.stderr


def test_cli_fail_on_threshold_is_separate_from_scan_failure(monkeypatch, tmp_path):
    _configure_test_scan(monkeypatch, tmp_path)
    report = dict(REPORT)
    report["findings"] = [{"check_id": "tls.certificate_expiry", "check": "Certificate expiry", "status": "fail",
                           "severity": "high", "evidence": "Expired.", "recommendation": "Renew."}]

    class FindingScanner:
        def __init__(self, **kwargs):
            pass

        def scan(self, url, *, profile):
            assert profile == "advanced"
            return SimpleNamespace(to_dict=lambda: report)

    monkeypatch.setattr("scanner.engine.Scanner", FindingScanner)
    result = CliRunner().invoke(cli.app, ["scan", "https://example.test", "--authorized", "--fail-on", "high"])

    assert result.exit_code == 1
    assert "Scan summary" in result.stdout


def test_cli_reports_collection_failure_with_runtime_exit_code(monkeypatch, tmp_path):
    _configure_test_scan(monkeypatch, tmp_path)
    failed_report = dict(REPORT)
    failed_report.update({"scan_status": "error", "errors": ["TLS verification failed."], "findings": []})

    class FailedScanner:
        def __init__(self, **kwargs):
            pass

        def scan(self, url, *, profile):
            assert profile == "advanced"
            return SimpleNamespace(to_dict=lambda: failed_report)

    monkeypatch.setattr("scanner.engine.Scanner", FailedScanner)
    result = CliRunner().invoke(cli.app, ["scan", "https://example.test", "--authorized", "--format", "json"])

    assert result.exit_code == 2
    assert '"scan_status": "error"' in result.stdout


def test_report_command_reads_saved_json_file(tmp_path):
    source = tmp_path / "scan.json"
    source.write_text(__import__("json").dumps(REPORT), encoding="utf-8")
    result = CliRunner().invoke(cli.app, ["report", str(source), "--format", "json"])
    assert result.exit_code == 0
    assert '"scan_id": "cli-test-scan"' in result.stdout
