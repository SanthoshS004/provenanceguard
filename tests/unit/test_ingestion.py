"""
Unit Tests for Secure Ingestion Pipeline
"""

import pytest

from provenanceguard.core.artifacts.ingestion import ingest_artifact
from provenanceguard.core.domain.enums import DigestAlgorithm, MediaType
from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.infrastructure.storage.filesystem import FilesystemStorageDriver


def test_ingest_artifact_success(tmp_path):
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage")
    payload = b"\x7fELF\x02\x01\x01\x00" + b"A" * 100

    artifact = ingest_artifact(
        stream_or_path=payload,
        organization_id="org_acme",
        project_id="proj_payments",
        name="payment-service",
        version="1.0.0",
        storage_driver=driver,
    )

    assert artifact.name == "payment-service"
    assert artifact.media_type == MediaType.ELF
    assert artifact.size_bytes == len(payload)

    sha256_digest = next(d for d in artifact.digests if d.algorithm == DigestAlgorithm.SHA256)
    assert len(sha256_digest.value) == 64
    assert driver.exists(f"org_acme/proj_payments/artifacts/{sha256_digest.value}")


def test_ingest_artifact_client_claimed_digest_success(tmp_path):
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage")
    payload = b"abc"
    # "abc" SHA-256 = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    claimed = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    artifact = ingest_artifact(
        stream_or_path=payload,
        organization_id="org_acme",
        project_id="proj_payments",
        name="payment-service",
        version="1.0.0",
        storage_driver=driver,
        claimed_digest=claimed,
    )
    assert artifact.size_bytes == 3


def test_ingest_artifact_client_claimed_digest_mismatch_rejection(tmp_path):
    """
    SECURITY TEST:
    Client-provided digest is treated as UNTRUSTED claim.
    Mismatch between calculated digest and client claimed digest MUST raise IngestionRejectedError!
    """
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage")
    payload = b"abc"
    fake_claim = "1111111111111111111111111111111111111111111111111111111111111111"

    with pytest.raises(IngestionRejectedError) as exc_info:
        ingest_artifact(
            stream_or_path=payload,
            organization_id="org_acme",
            project_id="proj_payments",
            name="payment-service",
            version="1.0.0",
            storage_driver=driver,
            claimed_digest=fake_claim,
        )

    assert exc_info.value.error_code == "PG-2003"
    assert "Client claimed digest mismatch" in str(exc_info.value)
