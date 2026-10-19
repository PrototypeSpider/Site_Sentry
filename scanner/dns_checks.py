"""Bounded DNS observations for an authorized hostname."""

from __future__ import annotations

import dns.exception
import dns.resolver


def observe_dns(hostname: str, *, timeout: float = 2.0, lifetime: float = 4.0) -> dict:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = timeout
    resolver.lifetime = lifetime
    records: dict[str, list[str]] = {}
    errors: dict[str, str] = {}
    for record_type in ("A", "AAAA", "CNAME", "NS", "TXT"):
        try:
            answer = resolver.resolve(hostname, record_type, search=False, raise_on_no_answer=False)
            records[record_type] = [item.to_text()[:500] for item in answer][:32] if answer.rrset else []
        except dns.resolver.NXDOMAIN:
            errors[record_type] = "name_not_found"
        except dns.resolver.NoAnswer:
            records[record_type] = []
        except (dns.exception.Timeout, dns.resolver.NoNameservers):
            errors[record_type] = "query_failed_or_timed_out"
    return {"hostname": hostname, "records": records, "errors": errors}
