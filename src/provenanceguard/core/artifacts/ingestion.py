"""
Secure Artifact Ingestion Pipeline Service.
Executes bounded streaming hash calculation, magic-byte media type detection,
untrusted client digest verification, 2 GB streaming size enforcement,
tenant-isolated storage key construction, and object storage persistence.
"""

import io
import uuid
from pathlib import Path
from typing import BinaryIO, Optional, Union

from provenanceguard.core.artifacts.detector import detect_media_type_from_stream
from provenanceguard.core.common.crypto import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_INGESTION_BYTES,
    calculate_stream_digests,
)
from provenanceguard.core.domain.entities import Artifact
from provenanceguard.core.domain.enums import DigestAlgorithm, MediaType
from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.core.domain.value_objects import ArtifactDigest
from provenanceguard.core.storage.ports import ObjectStorageDriver


def _validate_tenant_identifier(tenant_id: str, field_name: str) -> str:
    clean_id = tenant_id.strip()
    if not clean_id or "/" in clean_id or "\\" in clean_id or ".." in clean_id:
        raise IngestionRejectedError(
            error_code="PG-1001",
            message=(
                f"Invalid {field_name}: '{tenant_id}' contains prohibited path traversal characters"
            ),
        )
    return clean_id


def ingest_artifact(
    stream_or_path: Union[BinaryIO, Path, bytes],
    organization_id: str,
    project_id: str,
    name: str,
    version: str,
    storage_driver: ObjectStorageDriver,
    claimed_digest: Optional[Union[ArtifactDigest, str]] = None,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: int = DEFAULT_MAX_INGESTION_BYTES,
) -> Artifact:
    """
    Ingests an untrusted software artifact payload securely.

    :param stream_or_path: File-like binary stream, Path on disk, or raw bytes.
    :param organization_id: Validated tenant organization ID.
    :param project_id: Validated tenant project ID.
    :param name: Artifact name string.
    :param version: Artifact version string.
    :param storage_driver: Abstract ObjectStorageDriver implementation.
    :param claimed_digest: Optional client-provided claimed digest (treated as untrusted claim).
    :param chunk_size: Streaming buffer size in bytes (default 64 KiB).
    :param max_bytes: Ingestion upload size limit in bytes (default 2 GB).
    :return: Validated Artifact domain entity.
    :raises IngestionRejectedError: If streaming exceeds 2GB or digest mismatches.
    """
    clean_org = _validate_tenant_identifier(organization_id, "organization_id")
    clean_proj = _validate_tenant_identifier(project_id, "project_id")

    # Normalize input into seekable/readable binary stream
    if isinstance(stream_or_path, bytes):
        raw_stream: BinaryIO = io.BytesIO(stream_or_path)
    elif isinstance(stream_or_path, Path):
        if not stream_or_path.exists():
            raise IngestionRejectedError(
                error_code="PG-1001",
                message=f"Ingestion artifact file not found: {stream_or_path}",
            )
        raw_stream = open(stream_or_path, "rb")
    else:
        raw_stream = stream_or_path

    try:
        # 1. Detect Media Type via initial magic bytes
        media_type: MediaType = detect_media_type_from_stream(raw_stream)

        # Ensure stream is reset to beginning before hashing
        if raw_stream.seekable():
            raw_stream.seek(0)

        # 2. Calculate Streaming Cryptographic Hashes & Enforce 2 GB limit
        digests, total_bytes = calculate_stream_digests(
            raw_stream, chunk_size=chunk_size, max_bytes=max_bytes
        )

        sha256_digest = next(d for d in digests if d.algorithm == DigestAlgorithm.SHA256)

        # 3. Untrusted Client Digest Verification
        if claimed_digest is not None:
            claimed_value = (
                claimed_digest.value.strip().lower()
                if isinstance(claimed_digest, ArtifactDigest)
                else claimed_digest.strip().lower()
            )
            if sha256_digest.value != claimed_value:
                raise IngestionRejectedError(
                    error_code="PG-2003",
                    message=(
                        "Client claimed digest mismatch: calculated SHA-256 digest "
                        f"'{sha256_digest.value}' does not match claimed '{claimed_value}'"
                    ),
                    details=[
                        f"Calculated: {sha256_digest.value}",
                        f"Claimed:    {claimed_value}",
                    ],
                )

        # 4. Construct Tenant-Isolated Immutable Storage Key
        # Storage key structure: <organization_id>/<project_id>/artifacts/<sha256_hash>
        storage_key = f"{clean_org}/{clean_proj}/artifacts/{sha256_digest.value}"

        # 5. Persist Object Payload to Storage Driver
        if raw_stream.seekable():
            raw_stream.seek(0)

        storage_ref = storage_driver.put_object(
            storage_key=storage_key,
            data=raw_stream,
            length=total_bytes,
            content_type=media_type.value,
        )

        # 6. Instantiate & Return Validated Domain Entity
        artifact = Artifact(
            id=f"art_{uuid.uuid4().hex[:12]}",
            project_id=clean_proj,
            name=name,
            version=version,
            media_type=media_type,
            digests=digests,
            size_bytes=total_bytes,
            storage_reference=storage_ref,
        )

        return artifact

    finally:
        # Close file handle if we opened it from Path
        if isinstance(stream_or_path, Path) and not raw_stream.closed:
            raw_stream.close()
