"""
Security & Sandboxing Boundary Unit Tests
"""

from pathlib import Path

from provenanceguard.core.common.config import load_config


def test_worker_config_disallows_docker_socket():
    worker_config_path = Path("config/worker.yaml")
    assert worker_config_path.exists()

    config = load_config(worker_config_path)
    assert config["worker"]["mount_docker_socket"] is False, (
        "Docker socket MUST NOT be mounted inside workers"
    )
    assert config["worker"]["unprivileged_uid"] == 10001
