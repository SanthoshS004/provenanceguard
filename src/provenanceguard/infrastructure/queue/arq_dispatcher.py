"""ARQ & Redis TaskDispatcher implementation."""

import os

from arq.connections import ArqRedis, RedisSettings, create_pool

from provenanceguard.infrastructure.queue.dispatcher import JobPayload, TaskDispatcher


class ARQTaskDispatcher(TaskDispatcher):
    """ARQ and Redis task dispatcher implementation."""

    def __init__(
        self, redis_pool: ArqRedis | None = None, redis_settings: RedisSettings | None = None
    ):
        self._redis_pool = redis_pool
        self._redis_settings = redis_settings or RedisSettings(
            host=os.getenv("PG_REDIS_HOST", "localhost"),
            port=int(os.getenv("PG_REDIS_PORT", "6379")),
            password=os.getenv("PG_REDIS_PASSWORD", None),
        )

    async def get_pool(self) -> ArqRedis:
        if self._redis_pool is None:
            self._redis_pool = await create_pool(self._redis_settings)
        return self._redis_pool

    async def dispatch_verification_job(self, payload: JobPayload) -> str:
        # 1. Enforce payload size boundary & secret key rejection
        payload_bytes = (
            payload.to_json_bytes()
        )  # Raises PayloadSecurityError if secret detected or >16KB
        _ = payload_bytes

        # 2. Get ARQ pool and enqueue job
        pool = await self.get_pool()
        payload_dict = payload.model_dump(mode="json")

        job = await pool.enqueue_job(
            "run_verification_job",
            payload_dict,
            _job_id=f"job_{payload.job_id}",
        )
        return job.job_id if job else payload.job_id
