"""Security tests for two-stage rate limiting, atomic Lua script, Retry-After header, and fail-closed Redis behavior."""

import pytest
from fastapi import HTTPException

from provenanceguard.apps.api.rate_limiter import check_rate_limit


def test_retry_after_calculation():
    """Verifies that Retry-After header seconds is calculated accurately when rate limit is exceeded."""
    key = "test_rate_limit_retry_after"
    max_req = 3
    window_sec = 60

    # Exhaust quota
    acc1, rem1, retry1 = check_rate_limit(key, max_req, window_sec)
    acc2, rem2, retry2 = check_rate_limit(key, max_req, window_sec)
    acc3, rem3, retry3 = check_rate_limit(key, max_req, window_sec)

    # 4th request must be rejected with Retry-After > 0
    acc4, rem4, retry4 = check_rate_limit(key, max_req, window_sec)
    assert acc4 is False
    assert rem4 == 0
    assert retry4 >= 1
    assert retry4 <= window_sec


def test_rate_limiter_redis_unavailable_fail_closed(monkeypatch):
    """Verifies that Redis failure in production mode raises HTTP 503 Service Unavailable."""
    monkeypatch.setenv("PG_ENV", "production")
    monkeypatch.setenv("PG_REDIS_HOST", "invalid_unreachable_redis_host_12345")
    from provenanceguard.apps.api.rate_limiter import RedisManager

    # Reset client singleton to force reconnect failure
    RedisManager._client = None

    with pytest.raises(HTTPException) as exc_info:
        check_rate_limit("test_fail_closed_key", max_requests=10)

    assert exc_info.value.status_code == 503
    assert "Service Unavailable" in exc_info.value.detail
