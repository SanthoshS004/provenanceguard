"""
Unit Tests for Magic-Byte & Structural JSON Media Type Detector
INVARIANT TEST: Gzip header \x1f\x8b MUST be detected as MediaType.GZIP, NOT OCI.
"""

import io

from provenanceguard.core.artifacts.detector import (
    detect_media_type_from_bytes,
    detect_media_type_from_stream,
)
from provenanceguard.core.domain.enums import MediaType


def test_detect_elf_binary():
    header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    assert detect_media_type_from_bytes(header) == MediaType.ELF


def test_detect_gzip_stream_is_not_oci():
    """
    CRITICAL INVARIANT TEST:
    Gzip magic header \x1f\x8b MUST be classified as MediaType.GZIP, NOT OCI!
    """
    header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
    media_type = detect_media_type_from_bytes(header)
    assert media_type == MediaType.GZIP
    assert media_type != MediaType.UNKNOWN


def test_detect_zip_archive():
    header = b"\x50\x4b\x03\x04\x14\x00\x00\x00"
    assert detect_media_type_from_bytes(header) == MediaType.ZIP


def test_detect_tar_archive():
    header = b"\x00" * 257 + b"ustar\x0000" + b"\x00" * 200
    assert detect_media_type_from_bytes(header) == MediaType.TAR


def test_detect_spdx_json():
    json_bytes = b'{\n  "spdxVersion": "SPDX-2.3",\n  "SPDXID": "SPDXRef-DOCUMENT"\n}'
    assert detect_media_type_from_bytes(json_bytes) == MediaType.SPDX_JSON


def test_detect_cyclonedx_json():
    json_bytes = b'{\n  "bomFormat": "CycloneDX",\n  "specVersion": "1.5"\n}'
    assert detect_media_type_from_bytes(json_bytes) == MediaType.CYCLONEDX_JSON


def test_detect_generic_json():
    json_bytes = b'{\n  "name": "payment-service",\n  "version": "1.0.0"\n}'
    assert detect_media_type_from_bytes(json_bytes) == MediaType.JSON


def test_detect_unknown_binary():
    binary_bytes = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99"
    assert detect_media_type_from_bytes(binary_bytes) == MediaType.UNKNOWN


def test_detect_from_seekable_stream():
    stream = io.BytesIO(b"\x7fELF\x02\x01\x01\x00" + b"rest of payload")
    media_type = detect_media_type_from_stream(stream)
    assert media_type == MediaType.ELF
    # Assert stream position was preserved
    assert stream.tell() == 0
