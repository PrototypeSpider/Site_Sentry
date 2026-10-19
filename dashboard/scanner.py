"""Authenticated server-side client for the SiteSentry backend API.

The Streamlit server keeps the bearer token out of browser code and delegates all
target validation, network access, scanning, storage, and report generation to
the backend service.
"""

from __future__ import annotations

import os
import ipaddress
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import requests
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(PROJECT_ROOT / ".env", override=False)


class BackendError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None, payload: dict | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload or {}


def api_base_url() -> str:
    return os.getenv("SITESENTRY_API_URL", "http://127.0.0.1:5000").rstrip("/")


def api_token() -> str:
    return os.getenv("SITESENTRY_API_TOKEN", "").strip()


def normalize_url(value: str) -> str | None:
    """Normalize only for user convenience; backend validation remains authoritative."""
    value = value.strip()
    if not value:
        return None
    candidate = value if "://" in value else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password or parsed.query:
            return None
        # Accessing .port also detects malformed port syntax.
        port = parsed.port
        if port is not None and port != (443 if parsed.scheme.lower() == "https" else 80):
            return None
        if not parsed.hostname or "." not in parsed.hostname:
            return None
        return candidate
    except ValueError:
        return None


def _request(method: str, path: str, *, timeout: tuple[float, float] = (3.05, 15.0), **kwargs):
    token = api_token()
    if not token:
        raise BackendError("SiteSentry API token is not configured on the dashboard server.")
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {token}"
    base = api_base_url()
    parsed_base = urlsplit(base)
    if parsed_base.scheme not in {"http", "https"} or not parsed_base.hostname or parsed_base.username or parsed_base.password:
        raise BackendError("SITESENTRY_API_URL must be an HTTP(S) URL without embedded credentials.")
    if parsed_base.scheme == "http":
        try:
            local_host = parsed_base.hostname.lower() == "localhost" or ipaddress.ip_address(parsed_base.hostname).is_loopback
        except ValueError:
            local_host = False
        if not local_host:
            raise BackendError("Use HTTPS for a remote SiteSentry API; bearer tokens are not sent over remote HTTP.")
    kwargs.setdefault("allow_redirects", False)
    try:
        response = requests.request(method, f"{base}{path}", headers=headers, timeout=timeout, **kwargs)
    except requests.RequestException as exc:
        # Avoid displaying raw request exceptions, which can include deployment details.
        raise BackendError(f"Could not reach the SiteSentry API at {base}.") from exc
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not response.ok:
        if response.status_code == 401:
            message = "The SiteSentry API rejected its configured dashboard token (401)."
        elif response.status_code == 429:
            message = str(payload.get("error") or "The backend rejected this request due to a rate or queue limit.")
        elif response.status_code == 400:
            message = str(payload.get("message") or payload.get("error") or "The backend rejected the request.")
        elif response.status_code == 404:
            message = "The requested scan was not found in backend history."
        elif response.status_code == 409:
            message = "The requested report is not ready yet."
        else:
            message = f"SiteSentry API request failed with HTTP {response.status_code}."
        raise BackendError(message, status_code=response.status_code, payload=payload if isinstance(payload, dict) else {})
    if path.endswith("/report") and kwargs.get("params", {}).get("format") == "pdf":
        return response.content
    return payload


def health() -> dict[str, Any]:
    return _request("GET", "/api/health")


def create_scan(url: str, profile: str = "standard") -> dict[str, Any]:
    if profile not in {"quick", "standard", "advanced"}:
        raise BackendError("Scan level must be quick, standard, or advanced.")
    return _request("POST", "/api/scans", json={"url": url, "profile": profile})


def get_scan(scan_id: str) -> dict[str, Any]:
    return _request("GET", f"/api/scans/{scan_id}")


def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    result = _request("GET", "/api/scans", params={"limit": limit})
    return result.get("scans", [])


def get_findings(scan_id: str) -> list[dict[str, Any]]:
    result = _request("GET", f"/api/scans/{scan_id}/findings")
    return result.get("findings", [])


def get_workflow(scan_id: str) -> dict[str, dict[str, Any]]:
    return _request("GET", f"/api/scans/{scan_id}/workflow").get("workflow", {})


def update_workflow(scan_id: str, check_id: str, status: str, note: str = "") -> dict[str, Any]:
    if status not in {"open", "acknowledged", "fixed"} or len(note) > 500:
        raise BackendError("Finding status or note is invalid.")
    from urllib.parse import quote
    return _request("PUT", f"/api/scans/{scan_id}/findings/{quote(check_id, safe='')}/workflow", json={"status": status, "note": note})


def compare_scans(scan_id: str, baseline_id: str) -> dict[str, Any]:
    return _request("GET", f"/api/scans/{scan_id}/compare/{baseline_id}")


def get_report(scan_id: str) -> dict[str, Any]:
    return _request("GET", f"/api/scans/{scan_id}/report", params={"format": "json"})


def get_xai_report(scan_id: str) -> dict[str, Any]:
    return _request("GET", f"/api/scans/{scan_id}/xai-report")


def get_pdf_report(scan_id: str) -> bytes:
    return _request("GET", f"/api/scans/{scan_id}/report", params={"format": "pdf"})


def cancel_scan(scan_id: str) -> dict[str, Any]:
    return _request("POST", f"/api/scans/{scan_id}/cancel")


def list_models() -> list[dict[str, Any]]:
    return _request("GET", "/api/models").get("models", [])


def predict_model(model_id: str, features: dict[str, Any]) -> dict[str, Any]:
    return _request("POST", f"/api/models/{model_id}/predict", json={"features": features})
