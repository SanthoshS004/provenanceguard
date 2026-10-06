"""Two-Stage Atomic Redis Lua Rate Limiting & Security Headers Middleware.

Implements:
1. Stage 1 (Pre-Auth): Client IP-based rate limiting on unauthenticated/auth routes.
2. Stage 2 (Post-Auth): Tenant/Principal identity rate limiting on authenticated routes.
3. Atomic Lua sliding-window calculation returning Retry-After header details.
4. Fail-closed production semantics (HTTP 503 on Redis failure).
5. Strict Security Headers middleware.
"""

from __future__ import annotations

import ipaddress
import math
import os
import time
import uuid
from typing import Any, Callable

import redis
from fastapi import Depends, HTTPException, Request, Response, status
from starlette.middleware.base import BaseHTTPMiddleware

from provenanceguard.apps.api.auth import AuthUser, get_current_user

# Atomic Lua Script for sliding-window rate limiting
LUA_RATE_LIMIT_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, ARGV[1])
local count = redis.call('ZCARD', KEYS[1])
if count < tonumber(ARGV[2]) then
    redis.call('ZADD', KEYS[1], ARGV[3], ARGV[4])
    redis.call('EXPIRE', KEYS[1], 60)
    return {1, count + 1, tonumber(ARGV[2]) - count - 1, 0}
else
    local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    local oldest_ts = oldest[2] or ARGV[3]
    return {0, count, 0, tonumber(oldest_ts)}
end
"""


class RedisManager:
    """Singleton manager for Redis connection pool."""

    _client: redis.Redis | None = None

    @classmethod
    def get_client(cls) -> redis.Redis:
        if cls._client is None:
            redis_host = os.environ.get("PG_REDIS_HOST", "localhost")
            redis_port = int(os.environ.get("PG_REDIS_PORT", "6379"))
            redis_db = int(os.environ.get("PG_REDIS_DB", "0"))
            redis_password = os.environ.get("PG_REDIS_PASSWORD", None)

            cls._client = redis.Redis(
                host=redis_host,
                port=redis_port,
                db=redis_db,
                password=redis_password,
                decode_responses=True,
                socket_timeout=2.0,
                socket_connect_timeout=2.0,
            )
        return cls._client


def get_trusted_client_ip(request: Request) -> str:
    """Extracts client IP address safely considering trusted proxies."""
    peer_ip = request.client.host if request.client else "127.0.0.1"

    trusted_proxies_str = os.environ.get("PG_TRUSTED_PROXIES", "127.0.0.1,::1")
    trusted_ips = [ip.strip() for ip in trusted_proxies_str.split(",") if ip.strip()]

    is_peer_trusted = False
    try:
        peer_addr = ipaddress.ip_address(peer_ip)
        for t in trusted_ips:
            try:
                if peer_addr in ipaddress.ip_network(t, strict=False):
                    is_peer_trusted = True
                    break
            except ValueError:
                if peer_ip == t:
                    is_peer_trusted = True
                    break
    except ValueError:
        pass

    if is_peer_trusted:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Parse rightmost non-proxy IP or leftmost IP
            ips = [ip.strip() for ip in forwarded.split(",") if ip.strip()]
            if ips:
                return ips[0]

    return peer_ip


def check_rate_limit(
    key: str, max_requests: int = 100, window_seconds: int = 60
) -> tuple[bool, int, int]:
    """Executes atomic Lua script to check sliding-window rate limit.

    Returns (accepted: bool, remaining: int, retry_after_seconds: int).
    Raises HTTPException(503) on Redis failure in production mode.
    """
    now_ms = int(time.time() * 1000)
    window_ms = window_seconds * 1000
    window_start_ms = now_ms - window_ms
    request_uuid = str(uuid.uuid4())
    member_str = f"{now_ms}:{request_uuid}"

    try:
        client = RedisManager.get_client()
        result = client.eval(
            LUA_RATE_LIMIT_SCRIPT,
            1,
            key,
            window_start_ms,
            max_requests,
            now_ms,
            member_str,
        )
    except Exception as err:
        env = os.environ.get("PG_ENV", "production").lower()
        if env in ("production", "prod"):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Service Unavailable: Rate limiter backend unreachable.",
            ) from err
        # Fallback for local testing without Redis
        return True, max_requests, 0

    accepted = bool(result[0] == 1)
    remaining = int(result[2])
    oldest_ts = int(result[3])

    retry_after_seconds = 0
    if not accepted:
        diff_ms = (oldest_ts + window_ms) - now_ms
        retry_after_seconds = max(1, math.ceil(diff_ms / 1000.0))

    return accepted, remaining, retry_after_seconds


def require_post_auth_rate_limit(
    max_requests: int = 100, window_seconds: int = 60
) -> Callable[[AuthUser], AuthUser]:
    """Stage 2 Post-Auth Rate Limit dependency for authenticated routes."""

    def dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        key = f"rate_limit:tenant:{user.organization_id}:{user.user_id}"
        accepted, remaining, retry_after = check_rate_limit(key, max_requests, window_seconds)

        if not accepted:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for organization tenant.",
                headers={"Retry-After": str(retry_after)},
            )
        return user

    return dependency


class PreAuthRateLimitingMiddleware(BaseHTTPMiddleware):
    """Stage 1 Pre-Auth Rate Limiting middleware on unauthenticated / sensitive endpoints."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        # Pre-auth routes: auth endpoints or root API
        path = request.url.path
        if path.startswith("/api/v1/auth/tokens") or path.startswith("/api/v1/webhooks/"):
            client_ip = get_trusted_client_ip(request)
            key = f"rate_limit:pre_auth:ip:{client_ip}"
            accepted, remaining, retry_after = check_rate_limit(
                key, max_requests=60, window_seconds=60
            )

            if not accepted:
                return Response(
                    content='{"detail":"Rate limit exceeded for IP address."}',
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    headers={"Retry-After": str(retry_after), "Content-Type": "application/json"},
                )

        response = await call_next(request)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects strict security headers into all outgoing HTTP responses."""

    async def dispatch(self, request: Request, call_next: Callable[[Request], Any]) -> Response:
        response = await call_next(request)

        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Narrowly scoped development-only CSP for API documentation endpoints (/api/v1/docs, /api/v1/redoc)
        env = os.getenv("PG_ENV", "development").lower()
        path = request.url.path.rstrip("/")
        if env not in ("production", "prod") and path in ("/api/v1/docs", "/api/v1/redoc"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
                "img-src 'self' data: https://fastapi.tiangolo.com; "
                "font-src 'self' https://fonts.gstatic.com; "
                "connect-src 'self'; "
                "frame-ancestors 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; frame-ancestors 'none'"
            )

        # HSTS only on HTTPS in production
        if env == "production" and request.url.scheme.lower() == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=63072000; includeSubDomains; preload"
            )

        return response
