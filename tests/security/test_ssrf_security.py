"""Security tests for SSRF pre-flight validation and IP-pinning transport."""

import pytest

from provenanceguard.infrastructure.network.ssrf_guard import (
    SSRFValidationError,
    WebhookURLSecurityPolicy,
)


def test_ssrf_private_ip_and_metadata_rejection():
    """Verifies that private, loopback, link-local, and cloud metadata IPs are rejected."""
    blocked_ips = [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "169.254.1.1",
        "::1",
    ]
    for ip in blocked_ips:
        assert WebhookURLSecurityPolicy.is_ip_blocked(ip) is True


def test_webhook_creation_time_ssrf_rejection():
    """Verifies static/DNS SSRF validation at creation time."""
    # Userinfo rejected
    with pytest.raises(SSRFValidationError, match="credentials in URL"):
        WebhookURLSecurityPolicy.validate_url(
            "https://user:pass@example.com/webhook", allow_http=True
        )

    # HTTP in production mode rejected
    with pytest.raises(SSRFValidationError, match="HTTPS"):
        WebhookURLSecurityPolicy.validate_url("http://example.com/webhook", allow_http=False)

    # Loopback IP rejected
    with pytest.raises(SSRFValidationError, match="blocked private/metadata IP"):
        WebhookURLSecurityPolicy.validate_url("https://127.0.0.1/webhook", allow_http=True)

    # Cloud metadata IP rejected
    with pytest.raises(SSRFValidationError, match="blocked private/metadata IP"):
        WebhookURLSecurityPolicy.validate_url(
            "https://169.254.169.254/latest/meta-data/", allow_http=True
        )


def test_idp_jwks_uri_creation_time_ssrf_rejection():
    """Verifies IdP JWKS URI creation-time SSRF rejection."""
    with pytest.raises(SSRFValidationError, match="blocked private/metadata IP"):
        WebhookURLSecurityPolicy.validate_url(
            "https://10.0.0.5/.well-known/jwks.json", allow_http=True
        )


def test_safe_public_https_endpoint_acceptance():
    """Verifies public HTTPS endpoints pass validation."""
    normalized = WebhookURLSecurityPolicy.validate_url(
        "https://example.com/webhook", allow_http=True
    )
    assert normalized == "https://example.com/webhook"
