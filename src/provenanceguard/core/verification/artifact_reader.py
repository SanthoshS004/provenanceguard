"""
Bounded Read-Only Artifact Reader Architecture
"""

import hashlib
import io
from pathlib import Path
from typing import BinaryIO, Optional, Union

from provenanceguard.core.verification.exceptions import AuthoritativeDigestMismatchError


class BoundedArtifactReader:
    """
    Read-only bounded artifact reader.
    Provides safe, non-executing byte access to artifact streams/files with strict bounds,
    read size caps, and authoritative SHA-256 digest validation.
    """

    def __init__(
        self,
        artifact_source: Union[Path, str, BinaryIO],
        authoritative_digest: Optional[str] = None,
        max_read_cap_bytes: int = 10_485_760,  # 10 MB per read call
    ):
        self.max_read_cap_bytes = max_read_cap_bytes
        self._owned_stream: Optional[BinaryIO] = None

        if isinstance(artifact_source, (str, Path)):
            path = Path(artifact_source)
            if not path.exists():
                raise FileNotFoundError(f"Artifact file not found: {path}")
            self.stream: BinaryIO = open(path, "rb")
            self._owned_stream = self.stream
        elif hasattr(artifact_source, "read") and hasattr(artifact_source, "seek"):
            self.stream = artifact_source
        else:
            raise TypeError("artifact_source must be a file Path, str, or seekable BinaryIO stream")

        # Determine file size safely
        self.stream.seek(0, io.SEEK_END)
        self.file_size: int = self.stream.tell()
        self.stream.seek(0, io.SEEK_SET)

        # Validate authoritative whole-file SHA-256 digest if provided
        if authoritative_digest:
            calculated_digest = self._calculate_stream_sha256()
            if calculated_digest.lower() != authoritative_digest.lower():
                self.close()
                raise AuthoritativeDigestMismatchError(
                    expected=authoritative_digest,
                    calculated=calculated_digest,
                )

    def _calculate_stream_sha256(self) -> str:
        """Calculates streaming SHA-256 of whole file in 64 KiB chunks."""
        hasher = hashlib.sha256()
        self.stream.seek(0, io.SEEK_SET)
        while True:
            chunk = self.stream.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
        self.stream.seek(0, io.SEEK_SET)
        return hasher.hexdigest()

    def read_bytes_at(self, offset: int, size: int) -> bytes:
        """
        Reads an exact raw byte slice [offset : offset + size] from the artifact.
        Enforces strict bounds, non-negative checks, and maximum read caps.
        """
        if offset < 0:
            raise ValueError(f"Negative offset rejected: {offset}")
        if size < 0:
            raise ValueError(f"Negative read size rejected: {size}")
        if size > self.max_read_cap_bytes:
            raise ValueError(
                f"Requested read size ({size} bytes) exceeds maximum "
                f"read cap ({self.max_read_cap_bytes} bytes)"
            )
        if offset + size > self.file_size:
            raise ValueError(
                f"Read range [{offset}:{offset + size}] exceeds "
                f"artifact file bounds (size={self.file_size})"
            )

        self.stream.seek(offset, io.SEEK_SET)
        raw_bytes = self.stream.read(size)
        if len(raw_bytes) < size:
            raise ValueError(
                f"Truncated read: expected {size} bytes at offset {offset}, got {len(raw_bytes)}"
            )

        return raw_bytes

    def close(self):
        """Closes stream if owned by this reader."""
        if self._owned_stream and not self._owned_stream.closed:
            self._owned_stream.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
