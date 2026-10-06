"""
Streaming Cryptographic Hashing Engine using Python stdlib hashlib.
Computes SHA-256 and SHA-512 digests concurrently over streams or files
without loading entire payloads into RAM.
Enforces 2 GB upload limit during streaming.
"""

import hashlib
from pathlib import Path
from typing import BinaryIO, List, Tuple

from provenanceguard.core.domain.enums import DigestAlgorithm
from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.core.domain.value_objects import ArtifactDigest

DEFAULT_CHUNK_SIZE = 65536  # 64 KiB buffer chunk
DEFAULT_MAX_INGESTION_BYTES = 2 * 1024 * 1024 * 1024  # 2 GB max upload limit


def calculate_stream_digests(
    stream: BinaryIO,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: int = DEFAULT_MAX_INGESTION_BYTES,
) -> Tuple[List[ArtifactDigest], int]:
    """
    Computes SHA-256 and SHA-512 digests concurrently over a binary stream.
    Enforces maximum bytes limit during streaming reads.

    :param stream: Binary input stream (file-like object).
    :param chunk_size: Buffer chunk size in bytes (default 64 KiB).
    :param max_bytes: Maximum allowed ingestion payload size in bytes (default 2 GB).
    :return: Tuple of (list of ArtifactDigest value objects, total bytes read).
    :raises IngestionRejectedError: If byte stream exceeds max_bytes.
    """
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()
    total_bytes = 0

    while True:
        chunk = stream.read(chunk_size)
        if not chunk:
            break

        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise IngestionRejectedError(
                error_code="PG-1002",
                message=(
                    f"Artifact ingestion stream exceeded maximum size limit "
                    f"of {max_bytes} bytes (2 GB)"
                ),
                details=[f"Stream read reached {total_bytes} bytes before termination"],
            )

        sha256.update(chunk)
        sha512.update(chunk)

    digests = [
        ArtifactDigest(algorithm=DigestAlgorithm.SHA256, value=sha256.hexdigest()),
        ArtifactDigest(algorithm=DigestAlgorithm.SHA512, value=sha512.hexdigest()),
    ]

    return digests, total_bytes


def calculate_file_digests(
    file_path: Path,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    max_bytes: int = DEFAULT_MAX_INGESTION_BYTES,
) -> Tuple[List[ArtifactDigest], int]:
    """
    Helper function to compute streaming digests for a file path on disk.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"File not found for hashing: {file_path}")

    with open(file_path, "rb") as f:
        return calculate_stream_digests(f, chunk_size=chunk_size, max_bytes=max_bytes)
