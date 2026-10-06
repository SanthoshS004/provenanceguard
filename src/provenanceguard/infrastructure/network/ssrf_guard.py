"""SSRF IP-Pinning & Pre-Flight Validation Guard.

Provides:
1. WebhookURLSecurityPolicy: Validation at subscription/config creation time and delivery time.
2. IPPinningTransport: Custom httpx AsyncBaseTransport that connects directly to the pre-flight
   validated IP address while preserving SNI, Host header, and TLS certificate hostname verification.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import urllib.parse

import httpx


class SSRFValidationError(ValueError):
    """Raised when a URL or resolved IP violates SSRF security boundaries."""

    pass


# Private, loopback, link-local, multicast, and cloud metadata network blocks
BLOCKED_IP_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
]

METADATA_IPS = {"169.254.169.254", "169.254.169.253", "fd00:ec2::254"}


class WebhookURLSecurityPolicy:
    """SSRF validation policy for outbound webhooks and JWKS URIs."""

    @staticmethod
    def is_ip_blocked(ip_str: str) -> bool:
        """Checks whether an IP address falls into blocked private/loopback/metadata ranges."""
        if ip_str in METADATA_IPS:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for network in BLOCKED_IP_NETWORKS:
                if ip_obj in network:
                    return True
            return False
        except ValueError:
            return True

    @classmethod
    def resolve_and_validate_host(cls, hostname: str, port: int) -> list[str]:
        """Resolves hostname to IP addresses and validates none are blocked."""
        try:
            addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as err:
            raise SSRFValidationError(
                f"DNS resolution failed for hostname '{hostname}': {err}"
            ) from err

        resolved_ips: list[str] = []
        for _, _, _, _, sockaddr in addr_info:
            ip = sockaddr[0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        if not resolved_ips:
            raise SSRFValidationError(f"No IP addresses resolved for hostname '{hostname}'.")

        for ip in resolved_ips:
            if cls.is_ip_blocked(ip):
                raise SSRFValidationError(
                    f"SSRF violation: Hostname '{hostname}' resolved to blocked private/metadata IP address '{ip}'."
                )

        return resolved_ips

    @classmethod
    def validate_url(cls, url: str, allow_http: bool | None = None) -> str:
        """Validates a target URL statically and via DNS pre-flight.

        Returns normalized safe URL string if valid.
        """
        if allow_http is None:
            # Default: HTTP allowed only if PG_ENV is development or test
            env = os.environ.get("PG_ENV", "production").lower()
            allow_http = env in ("development", "test", "dev")

        try:
            parsed = urllib.parse.urlparse(url)
        except Exception as err:
            raise SSRFValidationError(f"Invalid URL format: {err}") from err

        if not parsed.scheme:
            raise SSRFValidationError("URL missing scheme.")

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise SSRFValidationError(f"Unsupported scheme '{scheme}'. Only HTTP/HTTPS allowed.")

        if not allow_http and scheme != "https":
            raise SSRFValidationError("Production environment requires HTTPS URLs.")

        if parsed.username or parsed.password:
            raise SSRFValidationError("URL userinfo (credentials in URL) is prohibited.")

        hostname = parsed.hostname
        if not hostname:
            raise SSRFValidationError("URL missing valid hostname.")

        port = parsed.port or (80 if scheme == "http" else 443)

        # Pre-flight DNS validation
        cls.resolve_and_validate_host(hostname, port)

        # Normalize URL string
        normalized_path = parsed.path or "/"
        normalized_url = urllib.parse.urlunparse(
            (
                scheme,
                parsed.netloc,
                normalized_path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        return normalized_url


class IPPinningTransport(httpx.AsyncBaseTransport):
    """httpx AsyncBaseTransport that resolves IP pre-flight and connects directly to the IP

    while preserving TLS SNI, Host header, and server certificate verification.
    """

    def __init__(self, allow_http: bool | None = None, verify_ssl: bool = True):
        self.allow_http = allow_http
        self.verify_ssl = verify_ssl
        self._inner_transport = httpx.AsyncHTTPTransport(verify=verify_ssl)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)

        # 1. Validate static & pre-flight DNS via SSRF policy
        # Get resolved safe IPs
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            raise SSRFValidationError("Request URL missing hostname.")

        port = parsed.port or (80 if parsed.scheme.lower() == "http" else 443)
        resolved_ips = WebhookURLSecurityPolicy.resolve_and_validate_host(hostname, port)
        target_ip = resolved_ips[0]

        # Format pinned URL with IP address
        scheme = parsed.scheme.lower()
        path_and_query = parsed.path or "/"
        if parsed.query:
            path_and_query += f"?{parsed.query}"

        # Handle IPv6 brackets if needed
        ip_host = f"[{target_ip}]" if ":" in target_ip else target_ip
        pinned_netloc = f"{ip_host}:{port}" if parsed.port else ip_host

        pinned_url = f"{scheme}://{pinned_netloc}{path_and_query}"

        # 2. Clone headers and ensure Host header reflects original hostname
        headers = request.headers.copy()
        if "Host" not in headers:
            headers["Host"] = f"{hostname}:{port}" if parsed.port else hostname

        # 3. Create pinned request with original SNI / extension
        pinned_request = httpx.Request(
            method=request.method,
            url=pinned_url,
            headers=headers,
            content=request.content,
            extensions={"sni_hostname": hostname.encode("ascii")},
        )

        # 4. Delegate to inner transport
        return await self._inner_transport.handle_async_request(pinned_request)

    async def aclose(self) -> None:
        await self._inner_transport.aclose()
