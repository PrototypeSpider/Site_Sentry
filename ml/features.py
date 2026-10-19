"""Leakage-aware structured features for labeled check records."""

FEATURE_VERSION = "1.0"
FEATURE_COLUMNS = ("https", "tls_verified", "tls_days_remaining", "hsts_present", "hsts_max_age", "csp_present", "csp_unsafe_inline", "x_content_type_options_nosniff", "referrer_policy_present", "permissions_policy_present", "frame_protection_present")


def extract_features(record: dict) -> dict[str, float]:
    headers = {str(k).lower(): str(v) for k, v in (record.get("headers") or {}).items()}
    hsts = headers.get("strict-transport-security", "").lower()
    max_age = 0.0
    for directive in hsts.split(";"):
        name, sep, value = directive.strip().partition("=")
        if sep and name.strip() == "max-age":
            try:
                max_age = max(0.0, float(value.strip().strip('"')))
            except ValueError:
                pass
    csp = headers.get("content-security-policy", "").lower()
    return {"https": float(bool(record.get("https"))), "tls_verified": float(record.get("tls_verified") is True),
            "tls_days_remaining": float(max(-3650, min(3650, record.get("tls_days_remaining") or 0))),
            "hsts_present": float(bool(hsts)), "hsts_max_age": min(max_age, 31_536_000.0), "csp_present": float(bool(csp)),
            "csp_unsafe_inline": float("'unsafe-inline'" in csp), "x_content_type_options_nosniff": float(headers.get("x-content-type-options", "").strip().lower() == "nosniff"),
            "referrer_policy_present": float(bool(headers.get("referrer-policy"))), "permissions_policy_present": float(bool(headers.get("permissions-policy"))),
            "frame_protection_present": float("frame-ancestors" in csp or headers.get("x-frame-options", "").strip().lower() in {"deny", "sameorigin"})}
