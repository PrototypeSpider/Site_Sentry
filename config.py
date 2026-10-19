"""Environment-backed service settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _parse_domains(value: str) -> frozenset[str]:
    return frozenset(item.strip().lower().rstrip(".") for item in value.split(",") if item.strip())


@dataclass(frozen=True, slots=True)
class Settings:
    database_path: str = "data/sitesentry.sqlite3"
    report_dir: str = "reports/out"
    allowed_domains: frozenset[str] = frozenset()
    api_token: str | None = None
    max_pending_scans: int = 16
    max_workers: int = 2
    per_minute_limit: int = 10
    daily_scan_quota: int = 100
    daily_quota_per_client: int = 20
    redis_url: str | None = None
    single_instance_mode: bool = True
    auth_mode: str = "static_token"
    connect_timeout: float = 3.05
    read_timeout: float = 7.0
    redis_namespace: str = "sitesentry"

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(os.getenv("SITESENTRY_DATABASE", "data/sitesentry.sqlite3"), os.getenv("SITESENTRY_REPORT_DIR", "reports/out"),
            _parse_domains(os.getenv("SITESENTRY_ALLOWED_DOMAINS", "")), os.getenv("SITESENTRY_API_TOKEN") or None,
            int(os.getenv("SITESENTRY_MAX_PENDING", "16")), int(os.getenv("SITESENTRY_MAX_WORKERS", "2")),
            int(os.getenv("SITESENTRY_RATE_PER_MINUTE", "10")), int(os.getenv("SITESENTRY_DAILY_QUOTA", "100")),
            int(os.getenv("SITESENTRY_DAILY_QUOTA_PER_CLIENT", "20")), os.getenv("SITESENTRY_REDIS_URL") or None,
            os.getenv("SITESENTRY_SINGLE_INSTANCE", "true").lower() in {"1","true","yes"},
            os.getenv("SITESENTRY_AUTH_MODE", "static_token"), float(os.getenv("SITESENTRY_CONNECT_TIMEOUT", "3.05")),
            float(os.getenv("SITESENTRY_READ_TIMEOUT", "7")), os.getenv("SITESENTRY_REDIS_NAMESPACE", "sitesentry"))
        if min(settings.max_pending_scans, settings.max_workers, settings.per_minute_limit, settings.daily_scan_quota, settings.daily_quota_per_client) < 1:
            raise ValueError("Queue, worker, and rate limits must be positive.")
        if min(settings.connect_timeout, settings.read_timeout) <= 0:
            raise ValueError("Network timeouts must be positive.")
        if any(not domain or "/" in domain or ":" in domain or " " in domain for domain in settings.allowed_domains):
            raise ValueError("Allowed domains must contain hostnames only.")
        if settings.auth_mode not in {"static_token", "proxy_identity"}:
            raise ValueError("SITESENTRY_AUTH_MODE must be static_token or proxy_identity.")
        if not settings.redis_namespace or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:_-" for char in settings.redis_namespace):
            raise ValueError("SITESENTRY_REDIS_NAMESPACE may contain only letters, digits, colon, underscore, or hyphen.")
        if settings.auth_mode=="static_token" and not settings.api_token:
            raise ValueError("SITESENTRY_API_TOKEN is required when static-token authentication is enabled.")
        if not settings.single_instance_mode and not settings.redis_url:
            raise ValueError("Multi-instance mode requires SITESENTRY_REDIS_URL for shared limits and queue coordination.")
        if not settings.single_instance_mode and settings.auth_mode=="static_token" and len(settings.api_token or "")<32:
            raise ValueError("Multi-instance mode requires a 32-character-or-longer static API token or trusted proxy identity mode.")
        Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
        Path(settings.report_dir).mkdir(parents=True, exist_ok=True)
        return settings
