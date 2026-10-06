"""
Security & Sandboxing Tests for Artifact Ingestion (Phase 2)

Validates:
- Streaming 2 GB upload limit enforcement
- Path traversal prevention in tenant organization and project identifiers
- Magic-byte spoofing resilience
"""

import io

import pytest

from provenanceguard.core.artifacts.detector import detect_media_type_from_bytes
from provenanceguard.core.artifacts.ingestion import ingest_artifact
from provenanceguard.core.domain.enums import MediaType
from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.infrastructure.storage.filesystem import FilesystemStorageDriver


def test_streaming_max_upload_size_limit(tmp_path):
    """
    SECURITY TEST:
    Verifies that payloads exceeding max_bytes (e.g. 2 GB cap) are aborted DURING STREAMING.
    """
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage")

    # Simulate stream exceeding small test limit (100 bytes)
    payload = b"X" * 150
    stream = io.BytesIO(payload)

    with pytest.raises(IngestionRejectedError) as exc_info:
        ingest_artifact(
            stream_or_path=stream,
            organization_id="org_acme",
            project_id="proj_pay",
            name="test-service",
            version="1.0.0",
            storage_driver=driver,
            max_bytes=100,  # Enforce 100 bytes limit for security test
        )

    assert exc_info.value.error_code == "PG-1002"
    assert "exceeded maximum size limit" in str(exc_info.value)


def test_tenant_path_traversal_rejection(tmp_path):
    """
    SECURITY TEST:
    Verifies that organization_id or project_id containing path traversal characters ('../')
    are REJECTED during ingestion before storage key construction.
    """
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage")
    payload = b"abc"

    with pytest.raises(IngestionRejectedError) as exc_info:
        ingest_artifact(
            stream_or_path=payload,
            organization_id="../../etc",  # Malicious path traversal org ID
            project_id="proj_pay",
            name="test-service",
            version="1.0.0",
            storage_driver=driver,
        )

    assert exc_info.value.error_code == "PG-1001"
    assert "path traversal" in str(exc_info.value).lower()


def test_magic_byte_spoofing_detection():
    """
    SECURITY TEST:
    Verifies that file extension / claimed name does NOT override magic-byte classification.
    """
    # Payload claims to be "payload.json" but starts with ELF magic bytes
    elf_payload = b"\x7fELF\x02\x01\x01\x00" + b'{"fake": "json"}'
    detected = detect_media_type_from_bytes(elf_payload)
    assert detected == MediaType.ELF
    assert detected != MediaType.JSON
