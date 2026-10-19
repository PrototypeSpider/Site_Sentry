"""Exercise shared authentication/rate/quota behavior across two Flask instances.

Set SITESENTRY_TEST_REDIS_URL to an isolated Redis database before running.
The test scanner is stubbed so no target is contacted.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import redis

from config import Settings
from app import create_app


class NoNetworkScanner:
    def __init__(self, **_kwargs):
        pass

    def scan(self, _url, *, profile="standard"):
        return SimpleNamespace(scan_status="error", errors=["verification stub"],
            to_dict=lambda: {"scan_status": "error", "errors": ["verification stub"], "findings": []})


def _phase(redis_url: str, namespace: str, *, per_minute: int, client_quota: int, expected: str) -> dict:
    token = "test-only-token-" + uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="sitesentry-redis-check-") as temp:
        def settings(name: str) -> Settings:
            return Settings(database_path=str(Path(temp) / f"{name}.sqlite3"),
                report_dir=str(Path(temp) / f"reports-{name}"), allowed_domains=frozenset({"example.com"}),
                api_token=token, max_pending_scans=4, max_workers=1, per_minute_limit=per_minute,
                daily_scan_quota=10, daily_quota_per_client=client_quota, redis_url=redis_url,
                single_instance_mode=False, auth_mode="static_token", redis_namespace=namespace)

        patcher = patch("app.Scanner", NoNetworkScanner)
        patcher.start()
        try:
            app_a = create_app(settings("a"))
            app_b = create_app(settings("b"))
            client_a, client_b = app_a.test_client(), app_b.test_client()
            auth = {"Authorization": f"Bearer {token}"}
            if client_a.get("/api/health").status_code != 401:
                raise AssertionError("An unauthenticated request was not rejected.")
            if client_a.get("/api/health", headers=auth).status_code != 200:
                raise AssertionError("A valid bearer token was rejected.")
            payload = {"url": "https://example.com", "profile": "standard"}
            first = client_a.post("/api/scans", headers=auth, json=payload)
            second = client_b.post("/api/scans", headers=auth, json=payload)
            if first.status_code != 202 or second.status_code != 429 or second.json.get("error") != expected:
                raise AssertionError(f"Shared enforcement failed: first={first.status_code}, second={second.status_code}, body={second.json}")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and app_a.extensions["sitesentry_store"].get_status(first.json["scan_id"]) == "queued":
                time.sleep(0.05)
            if app_a.extensions["sitesentry_store"].get_status(first.json["scan_id"]) != "error":
                raise AssertionError("Stubbed worker did not complete its queued scan before cleanup.")
            return {"first_request": first.status_code, "second_request": second.status_code,
                    "shared_rejection": expected, "unauthenticated": 401, "valid_auth": 200}
        finally:
            patcher.stop()


def main() -> None:
    redis_url = os.getenv("SITESENTRY_TEST_REDIS_URL")
    if not redis_url:
        raise SystemExit("Set SITESENTRY_TEST_REDIS_URL to an isolated Redis database; production SITESENTRY_REDIS_URL is intentionally not used.")
    client = redis.Redis.from_url(redis_url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
    client.ping()
    prefix = f"sitesentry:integration:{uuid.uuid4().hex}"
    try:
        rate = _phase(redis_url, prefix + ":rate", per_minute=1, client_quota=10, expected="rate_limit_exceeded")
        quota = _phase(redis_url, prefix + ":quota", per_minute=10, client_quota=1, expected="daily_client_quota_exceeded")
        print(json.dumps({"status": "ok", "instances": 2, "rate_limit": rate, "client_quota": quota,
                          "scanner_network_access": "stubbed"}, indent=2))
    finally:
        keys = list(client.scan_iter(match=prefix + "*"))
        if keys:
            client.delete(*keys)


if __name__ == "__main__":
    main()
