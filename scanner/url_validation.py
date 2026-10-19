"""Strict target validation and DNS policy for public web assessments."""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class TargetValidationError(ValueError):
    """The requested target violates the scanner's network policy."""


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    url: str
    hostname: str
    port: int
    addresses: tuple[str, ...]


def validate_target(url: str, *, allowed_domains: set[str] | None = None) -> ValidatedTarget:
    if not isinstance(url, str) or not url.strip() or len(url) > 2048:
        raise TargetValidationError("A URL between 1 and 2048 characters is required.")
    try:
        parsed = urlsplit(url.strip())
        port = parsed.port
    except ValueError as exc:
        raise TargetValidationError("The URL contains an invalid host or port.") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"}:
        raise TargetValidationError("Only http and https URLs are supported.")
    if not parsed.hostname:
        raise TargetValidationError("A hostname is required.")
    if parsed.username is not None or parsed.password is not None:
        raise TargetValidationError("Credentials in URLs are not allowed.")
    hostname = parsed.hostname.rstrip(".").lower()
    if not hostname or hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        raise TargetValidationError("Local and internal hostnames are prohibited.")
    effective_port = port or (443 if scheme == "https" else 80)
    if effective_port not in {80, 443}:
        raise TargetValidationError("Only standard HTTP and HTTPS ports are allowed.")
    if (scheme, effective_port) not in {("http", 80), ("https", 443)}:
        raise TargetValidationError("URL scheme and port do not match.")
    if allowed_domains and not any(hostname == domain or hostname.endswith("." + domain) for domain in allowed_domains):
        raise TargetValidationError("Target is outside the configured authorized domain scope.")
    try:
        literal = ipaddress.ip_address(hostname)
        resolved = {str(literal)}
    except ValueError:
        try:
            resolved = {item[4][0].split("%", 1)[0] for item in socket.getaddrinfo(hostname, effective_port, type=socket.SOCK_STREAM)}
        except (OSError, socket.gaierror) as exc:
            raise TargetValidationError("Hostname could not be resolved.") from exc
    if not resolved:
        raise TargetValidationError("Hostname did not resolve to any addresses.")
    for address in resolved:
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise TargetValidationError("Private, reserved, loopback, link-local and other non-public destinations are prohibited.")
    path = parsed.path or "/"
    normalized = urlunsplit((scheme, parsed.netloc, path, parsed.query, ""))
    return ValidatedTarget(normalized, hostname, effective_port, tuple(sorted(resolved)))
