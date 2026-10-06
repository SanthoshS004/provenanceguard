"""ARQ Worker Application Entrypoint."""

import os

from arq.connections import RedisSettings

from provenanceguard.apps.worker.worker import run_verification_job


async def startup(ctx: dict) -> None:
    from provenanceguard.apps.worker.worker_metrics import start_worker_metrics_server

    start_worker_metrics_server(port=9090)


class WorkerSettings:
    """ARQ Worker process configuration."""

    functions = [run_verification_job]
    on_startup = startup
    max_jobs = int(os.getenv("PG_WORKER_CONCURRENCY", "10"))
    job_timeout = int(os.getenv("PG_WORKER_TIMEOUT", "30"))
    redis_settings = RedisSettings(
        host=os.getenv("PG_REDIS_HOST", "localhost"),
        port=int(os.getenv("PG_REDIS_PORT", "6379")),
        password=os.getenv("PG_REDIS_PASSWORD", None),
    )


if __name__ == "__main__":
    from arq import run_worker

    run_worker(WorkerSettings)
