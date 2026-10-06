"""Prometheus Telemetry & Middleware Module for ProvenanceGuard API Gateway.

Implements:
- Bounded Prometheus metric counters, histograms, and gauges.
- Middleware for request duration and route template normalization.
- Internal dedicated metrics HTTP server listening on port 9090.
"""

from __future__ import annotations

import logging
import time
from typing import Callable

from fastapi import Request, Response
from prometheus_client import (
    Counter,
    Gauge,
    Histogram,
    start_http_server,
)
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# Prometheus Telemetry Instruments
HTTP_REQUESTS_TOTAL = Counter(
    "provenanceguard_http_requests_total",
    "Total count of HTTP requests processed by API Gateway.",
    ["method", "route", "status_code"],
)

HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "provenanceguard_http_request_duration_seconds",
    "Histogram of HTTP request durations in seconds.",
    ["method", "route"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

VERIFICATIONS_TOTAL = Counter(
    "provenanceguard_verifications_total",
    "Total count of supply-chain verification runs performed.",
    ["status", "risk_level"],
)

POLICY_EVALUATIONS_TOTAL = Counter(
    "provenanceguard_policy_evaluations_total",
    "Total count of policy evaluation decisions rendered.",
    ["result"],
)

ACTIVE_CONNECTIONS = Gauge(
    "provenanceguard_active_connections",
    "Gauge of active connections across infrastructure pools.",
    ["component"],
)


def get_normalized_route(request: Request) -> str:
    """Extracts FastAPI resolved route template to prevent high-cardinality label explosion.

    Maps parameterized routes (e.g. `/api/v1/verifications/123e4567-e89b-12d3-a456-426614174000`)
    to normalized template strings (e.g. `/api/v1/verifications/{verification_id}`).
    """
    route = request.scope.get("route")
    if route and hasattr(route, "path"):
        return route.path

    # Fallback path template mapping if scope route not resolved
    raw_path = request.url.path
    if raw_path.startswith("/api/v1/verifications/"):
        return "/api/v1/verifications/{verification_id}"
    elif raw_path.startswith("/api/v1/projects/"):
        return "/api/v1/projects/{project_id}"
    elif raw_path.startswith("/api/v1/policies/"):
        return "/api/v1/policies/{policy_id}"
    elif raw_path.startswith("/api/v1/webhooks/subscriptions/"):
        return "/api/v1/webhooks/subscriptions/{subscription_id}"
    elif raw_path.startswith("/api/v1/idp/configurations/"):
        return "/api/v1/idp/configurations/{idp_id}"

    return raw_path


class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    """FastAPI Middleware collecting HTTP request metrics with normalized route templates."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        response = await call_next(request)
        duration = time.perf_counter() - start_time

        method = request.method
        route = get_normalized_route(request)
        status_code = str(response.status_code)

        # Record HTTP metrics
        HTTP_REQUESTS_TOTAL.labels(method=method, route=route, status_code=status_code).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route).observe(duration)

        return response


def start_metrics_server(port: int = 9090) -> None:
    """Starts dedicated internal Prometheus metrics HTTP server on port 9090."""
    try:
        start_http_server(port)
        logger.info(f"Internal Prometheus metrics server listening on port {port}")
    except Exception as exc:
        logger.warning(f"Could not start internal metrics server on port {port}: {exc}")
