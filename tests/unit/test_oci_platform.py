"""
Unit tests for Deterministic OCI Multi-Platform Selection.
"""

import pytest

from provenanceguard.analyzers.oci.oci_adapters import (
    OCIAmbiguousPlatformError,
    OCIImageLayoutAdapter,
    OCIPlatformNotFoundError,
)
from provenanceguard.analyzers.oci.oci_spec import Descriptor, Platform


def test_exact_linux_amd64_platform_selection():
    adapter = OCIImageLayoutAdapter()
    desc_amd64 = Descriptor(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        size=100,
        platform=Platform(os="linux", architecture="amd64"),
    )
    desc_arm64 = Descriptor(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        size=100,
        platform=Platform(os="linux", architecture="arm64"),
    )
    descriptors = [desc_amd64, desc_arm64]

    selected = adapter._select_manifest(descriptors, Platform(os="linux", architecture="amd64"))
    assert selected.digest == desc_amd64.digest


def test_exact_platform_not_found_rejection():
    adapter = OCIImageLayoutAdapter()
    desc_amd64 = Descriptor(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        size=100,
        platform=Platform(os="linux", architecture="amd64"),
    )
    with pytest.raises(OCIPlatformNotFoundError):
        adapter._select_manifest([desc_amd64], Platform(os="windows", architecture="arm64"))


def test_ambiguous_platform_rejection():
    adapter = OCIImageLayoutAdapter()
    desc1 = Descriptor(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:1111111111111111111111111111111111111111111111111111111111111111",
        size=100,
        platform=Platform(os="linux", architecture="amd64"),
    )
    desc2 = Descriptor(
        mediaType="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        size=100,
        platform=Platform(os="linux", architecture="amd64"),
    )
    # 2 matching manifests without a variant discriminator
    with pytest.raises(OCIAmbiguousPlatformError):
        adapter._select_manifest([desc1, desc2], Platform(os="linux", architecture="amd64"))
