"""Security Tests for Worker Container Hardening & Secret Rejection."""

import os
import uuid

import pytest
import yaml

from provenanceguard.infrastructure.queue.dispatcher import JobPayload, PayloadSecurityError


def test_worker_container_security_invariants():
    """Verifies docker-compose.yml worker service adheres strictly to security controls."""
    compose_path = os.path.join(os.path.dirname(__file__), "..", "..", "docker-compose.yml")
    assert os.path.exists(compose_path)

    with open(compose_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    worker_config = config.get("services", {}).get("worker", {})
    assert worker_config.get("user") == "10001:10001"
    assert worker_config.get("read_only") is True
    assert "tmpfs" in worker_config

    volumes = worker_config.get("volumes", [])
    assert not any("docker.sock" in str(v) for v in volumes)


def test_worker_payload_secret_rejection():
    malformed_payload = {
        "verification_run_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "password": "super_secret_password_123",
    }

    with pytest.raises(PayloadSecurityError):
        JobPayload.validate_dict_security(malformed_payload)
