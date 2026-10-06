"""
OCI Domain Specifications and Pydantic Models.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# Media Type Constants
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_CONFIG_MEDIA_TYPE = "application/vnd.oci.image.config.v1+json"
OCI_LAYER_TAR_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar"
OCI_LAYER_GZIP_MEDIA_TYPE = "application/vnd.oci.image.layer.v1.tar+gzip"

DOCKER_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER_GZIP_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"

COSIGN_SIGNATURE_MEDIA_TYPE = "application/vnd.dev.cosign.simplesigning.v1+json"
IN_TOTO_DSSE_MEDIA_TYPE = "application/vnd.in-toto+json"


class Platform(BaseModel):
    os: Optional[str] = None
    architecture: Optional[str] = None
    variant: Optional[str] = None
    os_version: Optional[str] = Field(default=None, alias="os.version")
    os_features: List[str] = Field(default_factory=list, alias="os.features")


class Descriptor(BaseModel):
    mediaType: str
    digest: str
    size: int
    urls: List[str] = Field(default_factory=list)
    annotations: Dict[str, str] = Field(default_factory=dict)
    platform: Optional[Platform] = None
    artifactType: Optional[str] = None
    subject: Optional["Descriptor"] = None


class OCIManifest(BaseModel):
    schemaVersion: int = 2
    mediaType: Optional[str] = None
    config: Descriptor
    layers: List[Descriptor]
    annotations: Dict[str, str] = Field(default_factory=dict)
    subject: Optional[Descriptor] = None


class OCIIndex(BaseModel):
    schemaVersion: int = 2
    mediaType: Optional[str] = None
    manifests: List[Descriptor]
    annotations: Dict[str, str] = Field(default_factory=dict)
    subject: Optional[Descriptor] = None


class RootFS(BaseModel):
    type: str = "layers"
    diff_ids: List[str] = Field(default_factory=list)


class OCIImageConfig(BaseModel):
    architecture: str = ""
    os: str = ""
    config: Dict[str, Any] = Field(default_factory=dict)
    rootfs: RootFS
    history: List[Dict[str, Any]] = Field(default_factory=list)


class SymlinkMetadata(BaseModel):
    path: str
    target: str
    is_outside_root: bool = False


class NormalizedOCIImage(BaseModel):
    source_format: str  # OCI_IMAGE_LAYOUT or DOCKER_SAVE
    selected_manifest_digest: str
    config_digest: str
    manifest: OCIManifest
    config: Optional[OCIImageConfig] = None
    layers_compressed_digests: List[str]
    layers_uncompressed_diff_ids: List[str] = Field(default_factory=list)
    raw_blobs: Dict[str, bytes] = Field(default_factory=dict)
