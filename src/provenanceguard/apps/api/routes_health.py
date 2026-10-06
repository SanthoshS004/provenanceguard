"""Health & Readiness Diagnostic Routes for ProvenanceGuard REST Gateway.

Implements:
- GET /api/v1/health/liveness: Ultra-fast process-only liveness check.
- GET /api/v1/health/readiness: Concurrent dependency check (PostgreSQL, Redis, MinIO)
  bounded by an overall 5-second deadline.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Tuple

from fastapi import APIRouter, Response, status
from sqlalchemy import text

from provenanceguard import __version__
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.queue.arq_dispatcher import ARQTaskDispatcher
from provenanceguard.infrastructure.storage.s3 import MinIOStorageDriver

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/health", tags=["Health"])


@router.get("/liveness", status_code=status.HTTP_200_OK)
async def liveness_check() -> Dict[str, Any]:
    """Lightweight process-only liveness probe.

    Returns HTTP 200 OK to confirm the FastAPI application process and event loop are responsive.
    Does NOT execute database queries or remote service calls.
    """
    return {
        "status": "UP",
        "probe": "liveness",
        "service": "provenanceguard-api",
        "version": __version__,
    }


async def _check_database() -> Tuple[str, float]:
    """Asynchronously verifies PostgreSQL RLS database connection pool."""
    start_time = time.perf_counter()
    try:

        def _db_ping():
            db_manager = DatabaseManager()
            with db_manager.get_session() as session:
                session.execute(text("SELECT 1"))

        await asyncio.to_thread(_db_ping)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return "UP", latency_ms
    except Exception as exc:
        logger.error(f"Readiness check failed for PostgreSQL: {type(exc).__name__}")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return "DOWN", latency_ms


async def _check_redis() -> Tuple[str, float]:
    """Asynchronously verifies Redis task queue connectivity."""
    start_time = time.perf_counter()
    try:
        dispatcher = ARQTaskDispatcher()
        pool = await dispatcher.get_pool()
        await pool.ping()
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return "UP", latency_ms
    except Exception as exc:
        logger.error(f"Readiness check failed for Redis: {type(exc).__name__}")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return "DOWN", latency_ms


async def _check_storage() -> Tuple[str, float]:
    """Asynchronously verifies MinIO / S3 object storage connectivity."""
    start_time = time.perf_counter()
    try:

        def _storage_ping():
            import os

            endpoint = os.getenv("PG_MINIO_ENDPOINT", "localhost:9000")
            access_key = os.getenv("PG_MINIO_ACCESS_KEY", "minioadmin")
            secret_key = os.getenv("PG_MINIO_SECRET_KEY", "minioadminpassword")
            bucket_name = os.getenv("PG_MINIO_BUCKET", "provenanceguard-artifacts")
            driver = MinIOStorageDriver(
                endpoint=endpoint,
                access_key=access_key,
                secret_key=secret_key,
                bucket_name=bucket_name,
            )
            driver.client.bucket_exists(bucket_name)

        await asyncio.to_thread(_storage_ping)
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return "UP", latency_ms
    except Exception as exc:
        logger.error(f"Readiness check failed for MinIO: {type(exc).__name__}")
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return "DOWN", latency_ms


@router.get("/readiness")
async def readiness_check(response: Response) -> Dict[str, Any]:
    """Deep dependency diagnostic probe.

    Executes checks for PostgreSQL, Redis, and MinIO concurrently (`asyncio.gather`).
    Enforces an overall 5.0 second execution deadline (`asyncio.wait_for`).

    Returns:
    - HTTP 200 OK if all components report UP within 5.0 seconds.
    - HTTP 503 Service Unavailable if any check fails or times out.
    Payloads are strictly sanitized (no credentials, hosts, or stack traces).
    """
    overall_start = time.perf_counter()
    overall_deadline_sec = 5.0

    db_status, redis_status, storage_status = "DOWN", "DOWN", "DOWN"
    db_latency, redis_latency, storage_latency = 0.0, 0.0, 0.0

    try:
        results = await asyncio.wait_for(
            asyncio.gather(
                _check_database(),
                _check_redis(),
                _check_storage(),
                return_exceptions=True,
            ),
            timeout=overall_deadline_sec,
        )

        db_res, redis_res, storage_res = results

        if isinstance(db_res, tuple):
            db_status, db_latency = db_res
        if isinstance(redis_res, tuple):
            redis_status, redis_latency = redis_res
        if isinstance(storage_res, tuple):
            storage_status, storage_latency = storage_res

    except asyncio.TimeoutError:
        logger.error("Readiness check exceeded overall 5.0s deadline")
    except Exception as exc:
        logger.error(f"Readiness check unexpected error: {type(exc).__name__}")

    all_healthy = db_status == "UP" and redis_status == "UP" and storage_status == "UP"

    total_latency_ms = round((time.perf_counter() - overall_start) * 1000, 2)

    health_payload = {
        "status": "UP" if all_healthy else "DOWN",
        "probe": "readiness",
        "service": "provenanceguard-api",
        "version": __version__,
        "latency_ms": total_latency_ms,
        "components": {
            "database": {"status": db_status, "latency_ms": db_latency},
            "redis": {"status": redis_status, "latency_ms": redis_latency},
            "storage": {"status": storage_status, "latency_ms": storage_latency},
        },
    }

    if not all_healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return health_payload
