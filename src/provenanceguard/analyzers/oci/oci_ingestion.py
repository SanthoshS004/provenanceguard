"""
OCI Streaming Content-Addressable Integrity Verification Engine.
"""

import hashlib

from provenanceguard.analyzers.oci.oci_adapters import (
    OCIInvalidDescriptorSizeError,
    OCILayerCountMismatchError,
    OCIMalformedDigestError,
    validate_descriptor_size,
    validate_digest_syntax,
)
from provenanceguard.analyzers.oci.oci_spec import NormalizedOCIImage


class OCIImageIngestor:
    """
    Streaming content-addressable integrity engine for OCI images.
    Verifies all digest and descriptor size relationships before processing data.
    """

    def verify_integrity(self, normalized_image: NormalizedOCIImage) -> None:
        """
        Executes strict content-addressable verification chain over normalized OCI image.
        Raises OCIError sub-class on any integrity violation.
        """
        blobs = normalized_image.raw_blobs
        manifest = normalized_image.manifest
        config = normalized_image.config

        # 1. Validate selected manifest digest & size
        selected_manifest_digest = normalized_image.selected_manifest_digest
        validate_digest_syntax(selected_manifest_digest)

        if selected_manifest_digest in blobs:
            manifest_bytes = blobs[selected_manifest_digest]
            validate_descriptor_size(len(manifest_bytes))
            computed_manifest_digest = f"sha256:{hashlib.sha256(manifest_bytes).hexdigest()}"
            if computed_manifest_digest.lower() != selected_manifest_digest.lower():
                raise OCIMalformedDigestError(
                    f"Selected manifest digest mismatch: computed '{computed_manifest_digest}' "
                    f"does not match declared '{selected_manifest_digest}'"
                )

        # 2. Validate config descriptor size & digest syntax
        config_desc = manifest.config
        validate_descriptor_size(config_desc.size)
        validate_digest_syntax(config_desc.digest)

        # 3. Validate layer count equality if config is present
        if config is not None and len(manifest.layers) != len(config.rootfs.diff_ids):
            raise OCILayerCountMismatchError(
                f"Manifest layers count ({len(manifest.layers)}) does not match "
                f"config rootfs.diff_ids count ({len(config.rootfs.diff_ids)})"
            )

        config_digest = config_desc.digest
        if config_digest not in blobs:
            raise OCIMalformedDigestError(f"Config blob '{config_digest}' absent from image blobs")

        config_bytes = blobs[config_digest]
        if len(config_bytes) != config_desc.size:
            raise OCIInvalidDescriptorSizeError(
                f"Config blob size mismatch: expected {config_desc.size} bytes, got {len(config_bytes)} bytes"
            )

        computed_config_digest = f"sha256:{hashlib.sha256(config_bytes).hexdigest()}"
        if computed_config_digest.lower() != config_digest.lower():
            raise OCIMalformedDigestError(
                f"Config blob digest mismatch: computed '{computed_config_digest}' "
                f"does not match declared '{config_digest}'"
            )

        # 4. Validate compressed layer descriptors
        for idx, layer_desc in enumerate(manifest.layers):
            validate_descriptor_size(layer_desc.size)
            validate_digest_syntax(layer_desc.digest)

            layer_digest = layer_desc.digest
            if layer_digest not in blobs:
                raise OCIMalformedDigestError(
                    f"Layer blob '{layer_digest}' at index {idx} absent from blobs"
                )

            layer_bytes = blobs[layer_digest]
            if len(layer_bytes) != layer_desc.size:
                raise OCIInvalidDescriptorSizeError(
                    f"Layer {idx} blob size mismatch: expected {layer_desc.size} bytes, got {len(layer_bytes)} bytes"
                )

            computed_layer_digest = f"sha256:{hashlib.sha256(layer_bytes).hexdigest()}"
            if computed_layer_digest.lower() != layer_digest.lower():
                raise OCIMalformedDigestError(
                    f"Layer {idx} digest mismatch: computed '{computed_layer_digest}' "
                    f"does not match declared '{layer_digest}'"
                )
