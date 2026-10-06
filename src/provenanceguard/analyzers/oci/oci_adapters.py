"""
OCI & Docker Save Archive Format Adapters & Exceptions.
"""

import json
import re
from typing import Any, Dict, List, Optional

from provenanceguard.analyzers.oci.oci_spec import (
    DOCKER_CONFIG_MEDIA_TYPE,
    DOCKER_LAYER_GZIP_MEDIA_TYPE,
    DOCKER_MANIFEST_MEDIA_TYPE,
    OCI_MANIFEST_MEDIA_TYPE,
    Descriptor,
    NormalizedOCIImage,
    OCIImageConfig,
    OCIIndex,
    OCIManifest,
    Platform,
)


# Exception Classes
class OCIError(Exception):
    """Base exception for all OCI subsystem failures."""

    pass


class OCIPlatformNotFoundError(OCIError):
    pass


class OCIAmbiguousPlatformError(OCIError):
    pass


class OCIAmbiguousImageError(OCIError):
    pass


class OCIMediaTypeMismatchError(OCIError):
    pass


class OCIUnsupportedCompressionError(OCIError):
    pass


class OCIMalformedLayerError(OCIError):
    pass


class OCILayerCountMismatchError(OCIError):
    pass


class OCIInvalidDescriptorSizeError(OCIError):
    pass


class OCIMalformedDigestError(OCIError):
    pass


class OCIInvalidTarHeaderError(OCIError):
    pass


class OCIInvalidHardlinkError(OCIError):
    pass


class OCIMalformedWhiteoutError(OCIError):
    pass


class OCITraversalWhiteoutError(OCIError):
    pass


class OCIMalformedConfigError(OCIError):
    pass


class OCIResourceExceededError(OCIError):
    pass


class CosignDigestMismatchError(OCIError):
    pass


class CosignReferrerMissingError(OCIError):
    pass


def validate_digest_syntax(digest: str) -> None:
    """Validates digest string adheres strictly to <algorithm>:<hex>."""
    if not isinstance(digest, str):
        raise OCIMalformedDigestError(f"Digest must be a string, got {type(digest)}")
    pattern = r"^[a-z0-9]+:[a-f0-9]{32,128}$"
    if not re.match(pattern, digest, re.IGNORECASE):
        raise OCIMalformedDigestError(f"Malformed digest syntax: '{digest}'")


def validate_descriptor_size(size: int) -> None:
    """Validates descriptor size before allocating memory or reading blobs."""
    if not isinstance(size, int) or size <= 0 or size > 2 * 1024 * 1024 * 1024:  # 2 GB limit
        raise OCIInvalidDescriptorSizeError(f"Invalid descriptor size: {size}")


class OCIImageLayoutAdapter:
    """
    Format adapter for OCI 1.0/1.1 Image Layout archives (`index.json`, `blobs/sha256/*`).
    """

    def parse_layout(
        self,
        blobs: Dict[str, bytes],
        platform_selector: Optional[Platform] = None,
    ) -> NormalizedOCIImage:
        """Parses in-memory blobs dictionary representing OCI Layout archive."""
        if "index.json" not in blobs:
            raise OCIError("Missing 'index.json' in OCI Image Layout archive")

        try:
            index_data = json.loads(blobs["index.json"].decode("utf-8"))
            oci_index = OCIIndex.model_validate(index_data)
        except Exception as e:
            raise OCIMalformedConfigError(f"Failed to parse 'index.json': {str(e)}") from e

        if not oci_index.manifests:
            raise OCIError("OCI 'index.json' contains zero manifest descriptors")

        # Perform Multi-Platform Selection
        selected_descriptor = self._select_manifest(oci_index.manifests, platform_selector)

        # Validate descriptor size & digest
        validate_descriptor_size(selected_descriptor.size)
        validate_digest_syntax(selected_descriptor.digest)

        # Load Manifest Blob
        manifest_digest = selected_descriptor.digest
        if manifest_digest not in blobs:
            raise OCIError(f"OCI manifest blob '{manifest_digest}' missing from archive")

        try:
            manifest_data = json.loads(blobs[manifest_digest].decode("utf-8"))
            oci_manifest = OCIManifest.model_validate(manifest_data)
        except Exception as e:
            raise OCIMalformedConfigError(
                f"Failed to parse OCI manifest '{manifest_digest}': {str(e)}"
            ) from e

        # Validate Config Descriptor
        config_desc = oci_manifest.config
        validate_descriptor_size(config_desc.size)
        validate_digest_syntax(config_desc.digest)

        config_digest = config_desc.digest
        if config_digest not in blobs:
            raise OCIError(f"OCI config blob '{config_digest}' missing from archive")

        try:
            config_data = json.loads(blobs[config_digest].decode("utf-8"))
            oci_config = OCIImageConfig.model_validate(config_data)
        except Exception as e:
            raise OCIMalformedConfigError(
                f"Failed to parse OCI config '{config_digest}': {str(e)}"
            ) from e

        # Validate Manifest Layers count equals Config rootfs.diff_ids count
        if len(oci_manifest.layers) != len(oci_config.rootfs.diff_ids):
            raise OCILayerCountMismatchError(
                f"Manifest layers count ({len(oci_manifest.layers)}) does not match "
                f"config rootfs.diff_ids count ({len(oci_config.rootfs.diff_ids)})"
            )

        layers_compressed: List[str] = []
        for idx, layer_desc in enumerate(oci_manifest.layers):
            validate_descriptor_size(layer_desc.size)
            validate_digest_syntax(layer_desc.digest)
            if layer_desc.digest not in blobs:
                raise OCIError(
                    f"OCI layer blob '{layer_desc.digest}' at index {idx} missing from archive"
                )
            layers_compressed.append(layer_desc.digest)

        return NormalizedOCIImage(
            source_format="OCI_IMAGE_LAYOUT",
            selected_manifest_digest=manifest_digest,
            config_digest=config_digest,
            manifest=oci_manifest,
            config=oci_config,
            layers_compressed_digests=layers_compressed,
            layers_uncompressed_diff_ids=list(oci_config.rootfs.diff_ids),
            raw_blobs=blobs,
        )

    def _select_manifest(
        self,
        descriptors: List[Descriptor],
        selector: Optional[Platform] = None,
    ) -> Descriptor:
        """Deterministic platform selection logic."""
        # Filter image manifests (ignore index/attestation referrers if mixed)
        candidates: List[Descriptor] = []
        for d in descriptors:
            if d.mediaType in (OCI_MANIFEST_MEDIA_TYPE, DOCKER_MANIFEST_MEDIA_TYPE):
                candidates.append(d)

        if not candidates:
            # Fallback to all descriptors if none explicitly specified manifest mediaType
            candidates = list(descriptors)

        if selector is not None:
            matches: List[Descriptor] = []
            for desc in candidates:
                if desc.platform is not None:
                    if (
                        (selector.os is None or desc.platform.os == selector.os)
                        and (
                            selector.architecture is None
                            or desc.platform.architecture == selector.architecture
                        )
                        and (selector.variant is None or desc.platform.variant == selector.variant)
                    ):
                        matches.append(desc)
            if len(matches) == 0:
                raise OCIPlatformNotFoundError(
                    f"Zero manifests matched platform criteria: {selector}"
                )
            elif len(matches) > 1:
                raise OCIAmbiguousPlatformError(
                    f"Multiple ({len(matches)}) manifests matched platform criteria: {selector}"
                )
            return matches[0]

        # No selector provided
        if len(candidates) == 1:
            return candidates[0]
        else:
            # If multiple manifests exist without a selector, check if only 1 has platform
            if len(candidates) > 1:
                raise OCIAmbiguousPlatformError(
                    f"OCI index contains {len(candidates)} manifest candidates without platform selector"
                )
            return candidates[0]


class DockerSaveAdapter:
    """
    Format adapter for Docker Save archives (`manifest.json`, config JSON, layer tarballs).
    """

    def parse_archive(
        self,
        blobs: Dict[str, bytes],
        requested_image: Optional[str] = None,
    ) -> NormalizedOCIImage:
        """Parses in-memory blobs dictionary representing Docker Save archive."""
        if "manifest.json" not in blobs:
            raise OCIError("Missing 'manifest.json' in Docker Save archive")

        try:
            docker_manifest = json.loads(blobs["manifest.json"].decode("utf-8"))
        except Exception as e:
            raise OCIMalformedConfigError(
                f"Failed to parse Docker Save 'manifest.json': {str(e)}"
            ) from e

        if not isinstance(docker_manifest, list) or len(docker_manifest) == 0:
            raise OCIError("Docker Save 'manifest.json' must be a non-empty list")

        selected_entry: Optional[Dict[str, Any]] = None

        if requested_image is not None:
            for entry in docker_manifest:
                repo_tags = entry.get("RepoTags", [])
                if repo_tags and requested_image in repo_tags:
                    selected_entry = entry
                    break
            if selected_entry is None:
                raise OCIError(
                    f"Requested image '{requested_image}' not found in Docker Save RepoTags"
                )
        else:
            if len(docker_manifest) == 1:
                selected_entry = docker_manifest[0]
            else:
                raise OCIAmbiguousImageError(
                    f"Docker Save archive contains {len(docker_manifest)} images without an explicit selector"
                )

        config_file_name = selected_entry.get("Config")
        if not config_file_name or config_file_name not in blobs:
            raise OCIError(
                f"Docker Save config reference '{config_file_name}' missing from archive"
            )

        config_bytes = blobs[config_file_name]
        try:
            config_data = json.loads(config_bytes.decode("utf-8"))
            oci_config = OCIImageConfig.model_validate(config_data)
        except Exception as e:
            raise OCIMalformedConfigError(
                f"Failed to parse Docker Save config JSON '{config_file_name}': {str(e)}"
            ) from e

        layer_files: List[str] = selected_entry.get("Layers", [])
        if not isinstance(layer_files, list) or len(layer_files) == 0:
            raise OCIError("Docker Save image entry contains zero layers")

        if len(layer_files) != len(oci_config.rootfs.diff_ids):
            raise OCILayerCountMismatchError(
                f"Docker Save layers count ({len(layer_files)}) does not match "
                f"config rootfs.diff_ids count ({len(oci_config.rootfs.diff_ids)})"
            )

        layers_compressed: List[str] = []
        for _idx, layer_file in enumerate(layer_files):
            if layer_file not in blobs:
                raise OCIError(f"Docker Save layer tar file '{layer_file}' missing from archive")
            layer_bytes = blobs[layer_file]
            layer_digest = f"sha256:{import_sha256(layer_bytes)}"
            layers_compressed.append(layer_digest)

        # Synthesize normalized descriptors
        import hashlib

        config_digest = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"

        # Synthesize manifest JSON bytes for deterministic selected manifest digest calculation
        synthetic_manifest_dict = {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": DOCKER_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": len(config_bytes),
            },
            "layers": [
                {
                    "mediaType": DOCKER_LAYER_GZIP_MEDIA_TYPE,
                    "digest": layers_compressed[i],
                    "size": len(blobs[layer_files[i]]),
                }
                for i in range(len(layer_files))
            ],
        }
        synthetic_manifest_bytes = json.dumps(synthetic_manifest_dict, sort_keys=True).encode(
            "utf-8"
        )
        manifest_digest = f"sha256:{hashlib.sha256(synthetic_manifest_bytes).hexdigest()}"

        blobs[manifest_digest] = synthetic_manifest_bytes
        blobs[config_digest] = config_bytes

        oci_manifest = OCIManifest.model_validate(synthetic_manifest_dict)

        return NormalizedOCIImage(
            source_format="DOCKER_SAVE",
            selected_manifest_digest=manifest_digest,
            config_digest=config_digest,
            manifest=oci_manifest,
            config=oci_config,
            layers_compressed_digests=layers_compressed,
            layers_uncompressed_diff_ids=list(oci_config.rootfs.diff_ids),
            raw_blobs=blobs,
        )


def import_sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()
