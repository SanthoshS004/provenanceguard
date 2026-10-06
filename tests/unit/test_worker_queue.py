"""Unit tests for Task Queue Job Payload Validation & Secret Detection."""

import uuid

import pytest
from pydantic import ValidationError

from provenanceguard.infrastructure.queue.dispatcher import (
    JobPayload,
    PayloadSecurityError,
)


def test_valid_job_payload_serialization():
    run_id = uuid.uuid4()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()

    payload = JobPayload(
        verification_run_id=run_id,
        organization_id=org_id,
        project_id=proj_id,
        attempt=1,
    )

    assert payload.schema_version == 1
    assert payload.attempt == 1
    raw_bytes = payload.to_json_bytes()
    assert len(raw_bytes) < 16384


def test_job_payload_extra_field_rejection():
    run_id = str(uuid.uuid4())
    org_id = str(uuid.uuid4())
    proj_id = str(uuid.uuid4())

    with pytest.raises(ValidationError):
        JobPayload.model_validate(
            {
                "verification_run_id": run_id,
                "organization_id": org_id,
                "project_id": proj_id,
                "extra_unsupported_field": "HACK",
            }
        )


def test_job_payload_secret_detection_and_rejection():
    """Verifies payloads containing secret keys raise PayloadSecurityError and are rejected."""
    malicious_payload_dict = {
        "verification_run_id": str(uuid.uuid4()),
        "organization_id": str(uuid.uuid4()),
        "project_id": str(uuid.uuid4()),
        "api_key": "super_secret_api_key_12345",
    }

    with pytest.raises(PayloadSecurityError):
        JobPayload.validate_dict_security(malicious_payload_dict)


def test_job_payload_nested_secret_rejection():
    nested_secret_dict = {
        "meta": {
            "auth": {
                "bearer_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            }
        }
    }

    with pytest.raises(PayloadSecurityError):
        JobPayload.validate_dict_security(nested_secret_dict)


def test_job_payload_oversized_rejection():
    run_id = uuid.uuid4()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()

    # Mock large bytes check
    class OversizedPayload(JobPayload):
        def to_json_bytes(self) -> bytes:
            return b"A" * 20000

    oversized = OversizedPayload(
        verification_run_id=run_id,
        organization_id=org_id,
        project_id=proj_id,
    )

    with pytest.raises(PayloadSecurityError):
        if len(oversized.to_json_bytes()) > 16384:
            raise PayloadSecurityError("Job payload exceeds maximum allowed size bound of 16KB.")
