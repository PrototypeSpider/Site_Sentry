from __future__ import annotations

from types import SimpleNamespace

import pytest

from dashboard import scanner as dashboard_api


def test_dashboard_url_normalization_defers_final_scope_validation():
    assert dashboard_api.normalize_url("example.com") == "https://example.com"
    assert dashboard_api.normalize_url("http://example.com:80/path") == "http://example.com:80/path"
    assert dashboard_api.normalize_url("http://example.com:8080") is None
    assert dashboard_api.normalize_url("http://user:pass@example.com") is None
    assert dashboard_api.normalize_url("https://example.com/path?access_token=secret") is None
    assert dashboard_api.normalize_url("file:///etc/passwd") is None


def test_dashboard_client_sends_token_server_side_and_scoped_scan_fields(monkeypatch):
    monkeypatch.setenv("SITESENTRY_API_TOKEN", "dashboard-test-secret")
    monkeypatch.setenv("SITESENTRY_API_URL", "https://backend.test")
    captured = {}

    def fake_request(method, url, **kwargs):
        captured.update(method=method, url=url, **kwargs)
        return SimpleNamespace(ok=True, status_code=202, json=lambda: {"scan_id": "scan-1", "status": "queued"}, content=b"")

    monkeypatch.setattr(dashboard_api.requests, "request", fake_request)
    result = dashboard_api.create_scan("https://example.com", "standard")
    assert result["scan_id"] == "scan-1"
    assert captured["headers"]["Authorization"] == "Bearer dashboard-test-secret"
    assert captured["json"] == {"url": "https://example.com", "profile": "standard"}
    assert "dashboard-test-secret" not in captured["url"]


def test_dashboard_client_redacts_auth_rejection(monkeypatch):
    monkeypatch.setenv("SITESENTRY_API_TOKEN", "dashboard-test-secret")
    monkeypatch.setattr(dashboard_api.requests, "request", lambda *a, **k: SimpleNamespace(
        ok=False, status_code=401, json=lambda: {"error": "unauthorized"}, content=b""))
    with pytest.raises(dashboard_api.BackendError, match="rejected its configured dashboard token") as error:
        dashboard_api.health()
    assert "dashboard-test-secret" not in str(error.value)


def test_dashboard_refuses_remote_plain_http_api(monkeypatch):
    monkeypatch.setenv("SITESENTRY_API_TOKEN", "dashboard-test-secret")
    monkeypatch.setenv("SITESENTRY_API_URL", "http://backend.example.com")
    with pytest.raises(dashboard_api.BackendError, match="Use HTTPS for a remote"):
        dashboard_api.health()


def test_dashboard_pdf_download_returns_backend_bytes(monkeypatch):
    monkeypatch.setenv("SITESENTRY_API_TOKEN", "dashboard-test-secret")
    monkeypatch.setattr(dashboard_api.requests, "request", lambda *a, **k: SimpleNamespace(
        ok=True, status_code=200, json=lambda: {}, content=b"%PDF-backend-report"))
    assert dashboard_api.get_pdf_report("scan-1") == b"%PDF-backend-report"
