"""Bounded HTTP transport that connects only to validated IP addresses."""

from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

from .url_validation import TargetValidationError, ValidatedTarget, validate_target

MAX_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 5
USER_AGENT = "SiteSentry/0.1 (+passive authorized assessment)"


class SafeTransportError(RuntimeError):
    """A typed collection failure or target-policy rejection."""

    def __init__(self, message: str, *, code: str = "transport_error"):
        super().__init__(message)
        self.code = code


@dataclass(slots=True)
class HttpObservation:
    requested_url: str
    final_url: str
    status_code: int
    headers: dict[str, str]
    tls: dict[str, object] | None
    redirect_chain: list[str]
    body_bytes_read: int
    body_truncated: bool = False


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection pinned to a prevalidated address, with original SNI/host verification."""

    def __init__(self, hostname: str, port: int, address: str, timeout: float):
        super().__init__(hostname, port, timeout=timeout, context=ssl.create_default_context())
        self._validated_address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._validated_address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _safe_ip(address: str) -> bool:
    try:
        return ipaddress.ip_address(address.split("%", 1)[0]).is_global
    except ValueError:
        return False


class SafeTransport:
    def __init__(self, *, timeout: tuple[float, float] = (3.05, 7.0), allowed_domains: set[str] | None = None):
        self.connect_timeout, self.read_timeout = timeout
        self.allowed_domains = allowed_domains

    def observe(self, target: ValidatedTarget) -> HttpObservation:
        current = target.url
        redirects: list[str] = []
        for redirect_count in range(MAX_REDIRECTS + 1):
            try:
                safe = validate_target(current, allowed_domains=self.allowed_domains)
                response, connection = self._request(safe)
            except TargetValidationError as exc:
                raise SafeTransportError(f"Redirect destination rejected: {exc}", code="redirect_scope_rejected") from exc
            except ssl.SSLCertVerificationError as exc:
                raise SafeTransportError("TLS certificate chain or hostname verification failed.", code="tls_verification_failed") from exc
            except ssl.SSLError as exc:
                raise SafeTransportError("TLS negotiation failed.", code="tls_handshake_failed") from exc
            except (socket.timeout, TimeoutError) as exc:
                raise SafeTransportError("Connection timed out.", code="connection_timeout") from exc
            except socket.gaierror as exc:
                raise SafeTransportError("DNS resolution failed during collection.", code="dns_resolution_failed") from exc
            except (OSError, http.client.HTTPException) as exc:
                raise SafeTransportError("HTTP collection failed.", code="http_collection_failed") from exc
            try:
                location = response.getheader("Location")
                if response.status in {301, 302, 303, 307, 308}:
                    if not location:
                        raise SafeTransportError("Redirect response did not include a destination.", code="invalid_redirect")
                    if redirect_count >= MAX_REDIRECTS:
                        raise SafeTransportError("Redirect limit exceeded.", code="redirect_limit_exceeded")
                    current = urljoin(current, location)
                    redirects.append(current)
                    continue
                tls = self._tls_details(connection) if safe.url.startswith("https:") else None
                headers: dict[str, str] = {}
                for name, value in response.getheaders():
                    normalized_name = name.lower()
                    if normalized_name in headers:
                        headers[normalized_name] = headers[normalized_name] + ", " + value
                    else:
                        headers[normalized_name] = value
                body_bytes = 0
                try:
                    while body_bytes < MAX_RESPONSE_BYTES:
                        chunk = response.read(min(16_384, MAX_RESPONSE_BYTES - body_bytes))
                        if not chunk:
                            break
                        body_bytes += len(chunk)
                except socket.timeout as exc:
                    raise SafeTransportError("Response body read timed out.", code="read_timeout") from exc
                return HttpObservation(target.url, current, response.status, headers, tls, redirects, body_bytes, body_bytes >= MAX_RESPONSE_BYTES)
            finally:
                connection.close()
        raise SafeTransportError("Redirect limit exceeded.", code="redirect_limit_exceeded")

    def _request(self, target: ValidatedTarget) -> tuple[http.client.HTTPResponse, http.client.HTTPConnection]:
        address = next((item for item in target.addresses if _safe_ip(item)), None)
        if address is None:
            raise SafeTransportError("No public validated address is available.", code="no_public_address")
        parsed = urlsplit(target.url)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        if parsed.scheme == "https":
            connection: http.client.HTTPConnection = _PinnedHTTPSConnection(target.hostname, target.port, address, self.connect_timeout)
        else:
            connection = _PinnedHTTPConnection(target.hostname, target.port, address, self.connect_timeout)
        try:
            connection.request("GET", path, headers={"Host": _host_header(target), "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1", "Connection": "close"})
            if connection.sock:
                connection.sock.settimeout(self.read_timeout)
            return connection.getresponse(), connection
        except Exception:
            connection.close()
            raise

    @staticmethod
    def _tls_details(connection: http.client.HTTPConnection) -> dict[str, object] | None:
        try:
            sock = connection.sock
            cert = sock.getpeercert()
            return {"verified": True, "subject": cert.get("subject", ()), "issuer": cert.get("issuer", ()),
                    "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                    "version": sock.version(), "cipher": sock.cipher()}
        except (AttributeError, OSError, ssl.SSLError):
            return {"verified": True, "details_available": False}


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, hostname: str, port: int, address: str, timeout: float):
        super().__init__(hostname, port, timeout=timeout)
        self._validated_address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._validated_address, self.port), self.timeout)


def _host_header(target: ValidatedTarget) -> str:
    default = 443 if target.url.startswith("https:") else 80
    return target.hostname if target.port == default else f"{target.hostname}:{target.port}"
