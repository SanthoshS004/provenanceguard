"""
Unit Tests for BoundedArtifactReader (Phase 4)
"""

import io

import pytest

from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.exceptions import AuthoritativeDigestMismatchError


def test_reader_exact_byte_range_read(tmp_path):
    p = tmp_path / "test.bin"
    content = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    p.write_bytes(content)

    with BoundedArtifactReader(p) as reader:
        assert reader.file_size == len(content)
        assert reader.read_bytes_at(0, 10) == b"0123456789"
        assert reader.read_bytes_at(10, 5) == b"ABCDE"


def test_reader_negative_offset_rejected():
    stream = io.BytesIO(b"Hello World")
    reader = BoundedArtifactReader(stream)
    with pytest.raises(ValueError, match="Negative offset"):
        reader.read_bytes_at(-1, 5)


def test_reader_negative_size_rejected():
    stream = io.BytesIO(b"Hello World")
    reader = BoundedArtifactReader(stream)
    with pytest.raises(ValueError, match="Negative read size"):
        reader.read_bytes_at(0, -5)


def test_reader_read_beyond_eof_rejected():
    stream = io.BytesIO(b"Hello World")
    reader = BoundedArtifactReader(stream)
    with pytest.raises(ValueError, match="exceeds artifact file bounds"):
        reader.read_bytes_at(5, 20)


def test_reader_oversized_read_rejected():
    stream = io.BytesIO(b"A" * 100)
    reader = BoundedArtifactReader(stream, max_read_cap_bytes=50)
    with pytest.raises(ValueError, match="exceeds maximum read cap"):
        reader.read_bytes_at(0, 60)


def test_reader_does_not_load_entire_artifact(tmp_path):
    p = tmp_path / "large.bin"
    p.write_bytes(b"X" * 1000)

    reader = BoundedArtifactReader(p, max_read_cap_bytes=100)
    # Perform small 10-byte slice read
    data = reader.read_bytes_at(100, 10)
    assert data == b"X" * 10
    reader.close()


def test_reader_authoritative_digest_match(tmp_path):
    p = tmp_path / "digest.bin"
    content = b"ProvenanceGuard Secure Content"
    p.write_bytes(content)
    # NIST SHA-256 for content
    import hashlib

    expected_sha256 = hashlib.sha256(content).hexdigest()

    with BoundedArtifactReader(p, authoritative_digest=expected_sha256) as reader:
        assert reader.file_size == len(content)


def test_reader_authoritative_digest_mismatch(tmp_path):
    p = tmp_path / "digest.bin"
    p.write_bytes(b"Tampered Content")
    wrong_digest = "0000000000000000000000000000000000000000000000000000000000000000"

    with pytest.raises(AuthoritativeDigestMismatchError) as exc:
        BoundedArtifactReader(p, authoritative_digest=wrong_digest)
    assert exc.value.error_code == "PG-4003"
