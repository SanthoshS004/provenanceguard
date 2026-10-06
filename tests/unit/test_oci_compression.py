"""
Unit tests for OCI Layer Compression Contract.
"""

import gzip
import io

import pytest

from provenanceguard.analyzers.oci.oci_adapters import (
    OCIMediaTypeMismatchError,
    OCIResourceExceededError,
    OCIUnsupportedCompressionError,
)
from provenanceguard.analyzers.oci.oci_extraction import OCIHardenedExtractor
from provenanceguard.analyzers.oci.oci_spec import (
    OCI_LAYER_GZIP_MEDIA_TYPE,
    OCI_LAYER_TAR_MEDIA_TYPE,
)


def test_valid_gzip_layer_decompression():
    extractor = OCIHardenedExtractor()
    raw_tar = b"tar content dummy data"
    out_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=out_buf, mode="wb") as gz:
        gz.write(raw_tar)
    gz_bytes = out_buf.getvalue()

    decompressed, diff_id = extractor._decompress_layer(OCI_LAYER_GZIP_MEDIA_TYPE, gz_bytes)
    assert decompressed == raw_tar
    assert diff_id.startswith("sha256:")


def test_unsupported_compression_rejection():
    extractor = OCIHardenedExtractor()
    with pytest.raises(OCIUnsupportedCompressionError):
        extractor._decompress_layer("application/vnd.oci.image.layer.v1.tar+bzip2", b"dummy")


def test_media_type_and_header_mismatch_rejection():
    extractor = OCIHardenedExtractor()
    # Declared gzip, but payload is uncompressed
    with pytest.raises(OCIMediaTypeMismatchError):
        extractor._decompress_layer(
            OCI_LAYER_GZIP_MEDIA_TYPE, b"plain tar data without gzip header"
        )

    # Declared uncompressed tar, but payload has gzip magic header \x1f\x8b
    with pytest.raises(OCIMediaTypeMismatchError):
        extractor._decompress_layer(OCI_LAYER_TAR_MEDIA_TYPE, b"\x1f\x8b\x08dummy")


def test_decompression_ratio_exceeded_abort():
    extractor = OCIHardenedExtractor()
    # High compression ratio bomb: 15 MB of zeros compressed into very small gzip
    bomb_content = b"\x00" * (15 * 1024 * 1024)
    out_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=out_buf, mode="wb") as gz:
        gz.write(bomb_content)
    gz_bytes = out_buf.getvalue()

    with pytest.raises(OCIResourceExceededError):
        extractor._decompress_layer(OCI_LAYER_GZIP_MEDIA_TYPE, gz_bytes)
