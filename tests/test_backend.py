from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime

import pytest

from config import Settings
from scanner.checks import evaluate_observation
from scanner.engine import Scanner
from scanner.transport import HttpObservation
from scanner.transport import SafeTransport, SafeTransportError
from scanner.url_validation import TargetValidationError, validate_target
from app import create_app


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://example.com", "http://localhost", "http://127.0.0.1", "http://169.254.1.2", "https://example.com:8443", "https://user:pass@example.com"])
def test_rejects_invalid_or_private_targets(url):
    with pytest.raises(TargetValidationError):
        validate_target(url)


def test_scope_enforces_exact_domain_boundary(monkeypatch):
    monkeypatch.setattr("scanner.url_validation.socket.getaddrinfo", lambda *args, **kwargs: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))])
    assert validate_target("https://sub.example.com", allowed_domains={"example.com"}).hostname == "sub.example.com"
    with pytest.raises(TargetValidationError): validate_target("https://example.com.attacker.test", allowed_domains={"example.com"})


def test_header_rules_require_directive_quality():
    obs = HttpObservation("https://a.test", "https://a.test", 200, {"Strict-Transport-Security":"max-age=100", "X-Content-Type-Options":"wrong", "X-Frame-Options":"ALLOWALL"}, {"verified":True,"not_after":format_datetime(datetime.now(timezone.utc)+timedelta(days=365))}, [], 12)
    results = {f.check_id:f for f in evaluate_observation(obs)}
    assert results["header.hsts"].status == "warning"
    assert results["header.x_content_type_options"].status == "finding"
    assert results["header.clickjacking_protection"].status == "finding"


def test_flask_api_validates_and_returns_health(tmp_path, monkeypatch):
    settings = Settings(database_path=str(tmp_path/"db.sqlite"), report_dir=str(tmp_path/"reports"), allowed_domains=frozenset(), api_token="test", max_pending_scans=2, max_workers=1)
    app = create_app(settings)
    client = app.test_client()
    assert client.get("/api/health",headers={"Authorization":"Bearer test"}).status_code == 200
    assert client.post("/api/scans", headers={"Authorization":"Bearer test"},json={"url":"http://127.0.0.1"}).status_code == 400


def test_failed_scan_never_has_pass_findings():
    result = Scanner().scan("http://127.0.0.1")
    assert result.scan_status == "error"
    assert all(f.status != "pass" for f in result.findings)


def test_authorization_reference_is_not_part_of_admin_scan_api(tmp_path):
    settings = Settings(database_path=str(tmp_path/"db.sqlite"), report_dir=str(tmp_path/"reports"), allowed_domains=frozenset({"example.com"}),api_token="test")
    app = create_app(settings)
    response = app.test_client().post("/api/scans", headers={"Authorization":"Bearer test"},json={"url":"https://example.com", "authorization_ref":"../../evil"})
    assert response.status_code == 400


def test_header_case_normalization_and_body_truncation_metadata():
    obs = HttpObservation("https://a.test", "https://a.test", 200, {"strict-transport-security":"max-age=31536000"},
                          {"verified":True,"not_after":format_datetime(datetime.now(timezone.utc)+timedelta(days=365))}, [], 10, True)
    results = {f.check_id:f for f in evaluate_observation(obs)}
    assert results["header.hsts"].status == "pass"
    assert obs.body_truncated is True


def test_transport_types_dns_failure(monkeypatch):
    from scanner import transport
    from scanner.url_validation import ValidatedTarget
    target = ValidatedTarget("https://example.com/", "example.com", 443, ("93.184.216.34",))
    scanner = SafeTransport()
    monkeypatch.setattr(scanner, "_request", lambda safe: (_ for _ in ()).throw(socket.gaierror("no DNS")))
    with pytest.raises(SafeTransportError) as caught:
        scanner.observe(target)
    assert caught.value.code == "dns_resolution_failed"


def test_redirect_destination_revalidated(monkeypatch):
    from scanner import transport
    from scanner.url_validation import ValidatedTarget
    target = ValidatedTarget("https://example.com/", "example.com", 443, ("93.184.216.34",))
    monkeypatch.setattr(transport, "validate_target", lambda *args, **kwargs: (_ for _ in ()).throw(TargetValidationError("out of scope")))
    with pytest.raises(SafeTransportError) as caught:
        SafeTransport().observe(target)
    assert caught.value.code == "redirect_scope_rejected"


def test_ml_rejects_unlabeled_or_too_small_data(tmp_path):
    from ml.train import train
    dataset = tmp_path / "empty.csv"
    dataset.write_text("target_group,label,https,tls_verified,headers_json\n", encoding="utf-8")
    with pytest.raises(ValueError):
        train(dataset, tmp_path / "model.joblib")


def test_ml_requires_dataset_provenance(tmp_path):
    from ml.train import train
    dataset=tmp_path/"labels.csv"
    dataset.write_text("target_group,label,https,tls_verified,headers_json\n",encoding="utf-8")
    with pytest.raises(ValueError,match="20 labeled rows"):
        train(dataset,tmp_path/"model.joblib")


def test_ai_schema_and_redaction():
    from integrations.explainer import sanitize_evidence, validate_explanation
    redacted = sanitize_evidence({"headers": {"Authorization": "Bearer secret"}})
    assert "secret" not in str(redacted)
    with pytest.raises(ValueError):
        validate_explanation({"summary":"ok"})


def test_http_to_https_redirect_assessment(monkeypatch):
    import scanner.engine as engine
    from scanner.url_validation import ValidatedTarget
    from scanner.transport import HttpObservation
    monkeypatch.setattr(engine, "validate_target", lambda *args, **kwargs: ValidatedTarget("http://example.com/", "example.com", 80, ("93.184.216.34",)))
    monkeypatch.setattr(engine, "observe_dns", lambda hostname: {"records": {}, "errors": {}})
    monkeypatch.setattr(engine.SafeTransport, "observe", lambda self, target: HttpObservation("http://example.com/", "https://example.com/", 200, {}, {"verified":True,"not_after":format_datetime(datetime.now(timezone.utc)+timedelta(days=365))}, ["https://example.com/"], 12))
    result = engine.Scanner().scan("http://example.com/")
    redirect = next(item for item in result.findings if item.check_id == "http.https_redirect")
    assert redirect.status == "pass"
    assert redirect.ml_assessment["status"] == "not_configured"


def test_health_requires_bearer_token_when_configured(tmp_path):
    settings = Settings(database_path=str(tmp_path/"db.sqlite"), report_dir=str(tmp_path/"reports"), allowed_domains=frozenset({"example.com"}), api_token="secret")
    client = create_app(settings).test_client()
    assert client.get("/api/health").status_code == 401
    assert client.get("/api/health", headers={"Authorization":"Bearer secret"}).status_code == 200


def test_proxy_identity_mode_requires_https_and_identity(tmp_path):
    settings=Settings(database_path=str(tmp_path/"proxy.db"),report_dir=str(tmp_path/"proxy-reports"),allowed_domains=frozenset({"example.com"}),auth_mode="proxy_identity")
    client=create_app(settings).test_client()
    assert client.get("/api/scans").status_code==401
    assert client.get("/api/scans",headers={"X-Authenticated-User":"alice","X-Forwarded-Proto":"http"}).status_code==401
    assert client.get("/api/scans",headers={"X-Authenticated-User":"alice","X-Forwarded-Proto":"https"}).status_code==200


def test_scan_history_is_isolated_by_authenticated_identity(tmp_path, monkeypatch):
    settings=Settings(database_path=str(tmp_path/"owners.db"),report_dir=str(tmp_path/"owner-reports"),
        allowed_domains=frozenset({"example.com"}),auth_mode="proxy_identity",max_workers=1)
    client=create_app(settings).test_client()
    monkeypatch.setattr("app.validate_target",lambda value,**kwargs: type("Target",(),{"url":"https://example.com/"})())
    alice={"X-Authenticated-User":"alice","X-Forwarded-Proto":"https"}
    bob={"X-Authenticated-User":"bob","X-Forwarded-Proto":"https"}
    response=client.post("/api/scans",headers=alice,json={"url":"https://example.com"})
    assert response.status_code==202
    scan_id=response.json["scan_id"]
    assert client.get("/api/scans",headers=alice).json["scans"]
    assert client.get("/api/scans",headers=bob).json["scans"]==[]
    assert client.get(f"/api/scans/{scan_id}",headers=bob).status_code==404
    assert client.get(f"/api/scans/{scan_id}/findings",headers=bob).status_code==404


def test_scan_store_migrates_owner_column_and_filters_history(tmp_path):
    from storage import ScanStore
    store=ScanStore(str(tmp_path/"legacy.db"))
    store.create_scan("alice-scan","https://example.com/","2026-10-19T00:00:00+00:00","standard","alice")
    assert store.get_scan("alice-scan","alice")["owner_id"]=="alice"
    assert store.get_scan("alice-scan","bob") is None
    assert [scan["scan_id"] for scan in store.list_scans(owner_id="alice")]==["alice-scan"]
    assert store.list_scans(owner_id="bob")==[]


def test_multinstance_settings_require_redis(monkeypatch,tmp_path):
    monkeypatch.setenv("SITESENTRY_SINGLE_INSTANCE","false"); monkeypatch.delenv("SITESENTRY_REDIS_URL",raising=False)
    monkeypatch.setenv("SITESENTRY_API_TOKEN","x"*40)
    with pytest.raises(ValueError,match="REDIS_URL"): Settings.from_env()


def test_provider_verification_reports_missing_config_without_leaking_secrets(monkeypatch):
    from integrations.explainer import verify_provider
    monkeypatch.delenv("GEMINI_API_KEY",raising=False); monkeypatch.delenv("GEMINI_MODEL",raising=False)
    result=verify_provider("gemini")
    assert result["status"]=="not_configured"
    assert "GEMINI_API_KEY" not in str(result)


def test_provider_live_verification_validates_structured_response(monkeypatch):
    import os
    import sys
    import types
    from integrations.explainer import verify_provider
    class Models:
        def generate_content(self,**kwargs):
            return types.SimpleNamespace(text=json.dumps({"summary":"Insufficient evidence.","evidence":"Synthetic only.","potential_impact":"Unknown.","remediation":"Keep deterministic checks authoritative.","limitations":"Smoke test."}))
    class Client:
        def __init__(self,**kwargs): self.models=Models()
    fake_genai=types.SimpleNamespace(Client=Client)
    fake_google=types.ModuleType("google"); fake_google.genai=fake_genai
    monkeypatch.setitem(sys.modules,"google",fake_google)
    monkeypatch.setitem(sys.modules,"google.genai",fake_genai)
    monkeypatch.setenv("GEMINI_API_KEY","test-secret"); monkeypatch.setenv("GEMINI_MODEL","test-model")
    monkeypatch.setenv("AI_PROVIDER","gemini")
    result=verify_provider("gemini")
    assert result["status"]=="ok" and result["response"]["summary"]=="Insufficient evidence."
    assert "test-secret" not in str(result)


def test_provider_cli_override_checks_requested_provider_config(monkeypatch):
    from integrations.explainer import verify_provider
    monkeypatch.setenv("AI_PROVIDER", "")
    monkeypatch.setenv("GEMINI_API_KEY", "test-secret")
    monkeypatch.setenv("GEMINI_MODEL", "test-model")
    import sys, types
    class Models:
        def generate_content(self, **kwargs):
            return types.SimpleNamespace(text=json.dumps({"summary":"ok","evidence":"synthetic","potential_impact":"unknown","remediation":"none","limitations":"smoke"}))
    class Client:
        def __init__(self, **kwargs): self.models=Models()
    fake=types.SimpleNamespace(Client=Client)
    module=types.ModuleType("google"); module.genai=fake
    monkeypatch.setitem(sys.modules,"google",module); monkeypatch.setitem(sys.modules,"google.genai",fake)
    assert verify_provider("gemini")["status"]=="ok"


def test_provider_failure_does_not_echo_credentials(monkeypatch):
    from integrations.explainer import verify_provider
    import sys, types
    class AuthError(Exception):
        status_code=401
    class Models:
        def generate_content(self, **kwargs): raise AuthError("request included top-secret-key")
    class Client:
        def __init__(self, **kwargs): self.models=Models()
    fake=types.SimpleNamespace(Client=Client)
    module=types.ModuleType("google"); module.genai=fake
    monkeypatch.setitem(sys.modules,"google",module); monkeypatch.setitem(sys.modules,"google.genai",fake)
    monkeypatch.setenv("AI_PROVIDER", "gemini"); monkeypatch.setenv("GEMINI_API_KEY", "top-secret-key"); monkeypatch.setenv("GEMINI_MODEL", "test-model")
    result=verify_provider("gemini")
    assert result["status"]=="error" and result["http_status_code"]==401
    assert "top-secret-key" not in str(result)


def test_configuration_ml_rule_baseline_uses_deterministic_scanner_rules():
    from ml.train import _rule_baseline_label
    safe={"target_group":"one","label":"compliant","https":"true","tls_verified":"true","tls_days_remaining":"90",
          "headers_json":json.dumps({"Strict-Transport-Security":"max-age=31536000","Content-Security-Policy":"default-src 'self'; frame-ancestors 'none'",
              "X-Content-Type-Options":"nosniff","Referrer-Policy":"strict-origin-when-cross-origin","Permissions-Policy":"camera=()"})}
    unsafe={**safe,"https":"false","tls_verified":"false","tls_days_remaining":"0","headers_json":"{}"}
    assert _rule_baseline_label(safe)=="compliant"
    assert _rule_baseline_label(unsafe)=="review"


def test_daily_quota_is_enforced(tmp_path):
    settings=Settings(database_path=str(tmp_path/"db.sqlite"),report_dir=str(tmp_path/"reports"),allowed_domains=frozenset({"example.com"}),api_token="secret",per_minute_limit=5,daily_scan_quota=1,daily_quota_per_client=5)
    client=create_app(settings).test_client(); headers={"Authorization":"Bearer secret"}
    # Hold work so the accepted request is still represented in persistent quota.
    first=client.post("/api/scans",headers=headers,json={"url":"https://example.com","profile":"standard"})
    second=client.post("/api/scans",headers=headers,json={"url":"https://example.com","profile":"standard"})
    assert first.status_code==202
    assert second.status_code==429


def test_cancel_queued_scan_is_persisted_and_worker_skips(tmp_path, monkeypatch):
    settings=Settings(database_path=str(tmp_path/"db.sqlite"),report_dir=str(tmp_path/"reports"),allowed_domains=frozenset({"example.com"}),api_token="secret",per_minute_limit=10,daily_scan_quota=10,daily_quota_per_client=10)
    client=create_app(settings).test_client(); headers={"Authorization":"Bearer secret"}
    from storage import ScanStore
    store=client.application.extensions["sitesentry_store"]
    owner="token:"+__import__("hashlib").sha256(b"secret").hexdigest()[:24]
    store.create_scan("queued-id","https://example.com/","2026-10-19T00:00:00+00:00",owner_id=owner)
    response=client.post("/api/scans/queued-id/cancel",headers=headers)
    assert response.status_code==200
    assert client.get("/api/scans/queued-id",headers=headers).json["status"]=="cancelled"
    assert store.get_status("queued-id")=="cancelled"
