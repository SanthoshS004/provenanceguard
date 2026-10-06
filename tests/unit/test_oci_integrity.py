"""
Unit tests for Descriptor Size, Syntax & Content-Addressable Integrity.
"""

import pytest

from provenanceguard.analyzers.oci.oci_adapters import (
    OCIInvalidDescriptorSizeError,
    OCILayerCountMismatchError,
    OCIMalformedDigestError,
    validate_descriptor_size,
    validate_digest_syntax,
)
from provenanceguard.analyzers.oci.oci_ingestion import OCIImageIngestor
from provenanceguard.analyzers.oci.oci_spec import (
    Descriptor,
    NormalizedOCIImage,
    OCIImageConfig,
    OCIManifest,
    RootFS,
)


def test_descriptor_size_validation():
    validate_descriptor_size(100)  # Valid

    with pytest.raises(OCIInvalidDescriptorSizeError):
        validate_descriptor_size(0)

    with pytest.raises(OCIInvalidDescriptorSizeError):
        validate_descriptor_size(-50)

    with pytest.raises(OCIInvalidDescriptorSizeError):
        validate_descriptor_size(3 * 1024 * 1024 * 1024)  # 3 GB > 2 GB limit


def test_malformed_digest_syntax():
    validate_digest_syntax(
        "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    )

    with pytest.raises(OCIMalformedDigestError):
        validate_digest_syntax("not-a-digest")

    with pytest.raises(OCIMalformedDigestError):
        validate_digest_syntax("sha256:short")


def test_layer_count_vs_diff_ids_mismatch_rejection():
    ingestor = OCIImageIngestor()

    manifest = OCIManifest(
        config=Descriptor(
            mediaType="application/vnd.oci.image.config.v1+json",
            digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
            size=10,
        ),
        layers=[
            Descriptor(
                mediaType="application/vnd.oci.image.layer.v1.tar+gzip",
                digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
                size=10,
            ),
            Descriptor(
                mediaType="application/vnd.oci.image.layer.v1.tar+gzip",
                digest="sha256:3333333333333333333333333333333333333333333333333333333333333333",
                size=10,
            ),
        ],
    )

    config = OCIImageConfig(
        rootfs=RootFS(
            diff_ids=["sha256:2222222222222222222222222222222222222222222222222222222222222222"]
        )  # Only 1 diff_id vs 2 layers
    )

    norm_img = NormalizedOCIImage(
        source_format="OCI_IMAGE_LAYOUT",
        selected_manifest_digest="sha256:0000000000000000000000000000000000000000000000000000000000000000",
        config_digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        manifest=manifest,
        config=config,
        layers_compressed_digests=[
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        ],
        layers_uncompressed_diff_ids=[
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        ],
        raw_blobs={},
    )

    with pytest.raises(OCILayerCountMismatchError):
        ingestor.verify_integrity(norm_img)
