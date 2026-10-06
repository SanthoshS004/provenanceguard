"""
OCI Container Image Analyzer Package
"""

from provenanceguard.analyzers.oci.oci_spec import (
    Descriptor,
    NormalizedOCIImage,
    OCIImageConfig,
    OCIIndex,
    OCIManifest,
    Platform,
    RootFS,
    SymlinkMetadata,
)

__all__ = [
    "Descriptor",
    "OCIManifest",
    "OCIIndex",
    "OCIImageConfig",
    "RootFS",
    "SymlinkMetadata",
    "NormalizedOCIImage",
    "Platform",
]
