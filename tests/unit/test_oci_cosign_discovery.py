"""
Unit tests for Offline OCI Discovery & Cosign/DSSE Verifier.
"""

import json

from provenanceguard.analyzers.oci.oci_spec import (
    Descriptor,
    NormalizedOCIImage,
    OCIManifest,
)
from provenanceguard.core.verification.oci_sigstore import (
    OCISigstoreVerifier,
    SignerAuthorizationPolicy,
)
from provenanceguard.core.verification.trust import VerificationTrustMaterial


def test_cosign_claimed_digest_mismatch_rejection():
    verifier = OCISigstoreVerifier()

    target_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    wrong_digest = "sha256:9999999999999999999999999999999999999999999999999999999999999999"

    # Create simple signing payload referencing wrong_digest
    payload = {
        "critical": {
            "image": {"docker-manifest-digest": wrong_digest},
            "type": "cosign container image signature",
        }
    }
    art_bytes = json.dumps(payload).encode("utf-8")

    report = verifier._verify_cosign_simple_signing(
        art_bytes=art_bytes,
        target_digest=target_digest,
        trust_material=VerificationTrustMaterial(),
        signer_policy=SignerAuthorizationPolicy(),
        sigstore_verifier=None,
    )

    assert report.status == "COSIGN_DIGEST_MISMATCH"
    assert not report.signature_verified


def test_missing_referrer_evidence_status():
    verifier = OCISigstoreVerifier()
    target_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

    norm_img = NormalizedOCIImage(
        source_format="OCI_IMAGE_LAYOUT",
        selected_manifest_digest=target_digest,
        config_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        manifest=OCIManifest(
            config=Descriptor(
                mediaType="app/json",
                digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
                size=10,
            ),
            layers=[],
        ),
        config=None,  # Not needed for discovery test
        layers_compressed_digests=[],
        layers_uncompressed_diff_ids=[],
        raw_blobs={},  # Empty raw blobs -> no referrers present
    )

    reports = verifier.verify_oci_image_signatures(
        normalized_image=norm_img,
        trust_material=VerificationTrustMaterial(),
    )

    assert len(reports) == 1
    assert reports[0].status == "COSIGN_REFERRER_MISSING"
    assert not reports[0].signature_verified


def test_offline_archive_zero_network_discovery(monkeypatch):
    """Verifies that offline OCI discovery makes zero network calls."""

    def forbidden_connect(*args, **kwargs):
        raise RuntimeError("Forbidden network call attempted during offline discovery")

    import socket

    monkeypatch.setattr(socket.socket, "connect", forbidden_connect)

    verifier = OCISigstoreVerifier()
    target_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

    norm_img = NormalizedOCIImage(
        source_format="OCI_IMAGE_LAYOUT",
        selected_manifest_digest=target_digest,
        config_digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
        manifest=OCIManifest(
            config=Descriptor(
                mediaType="app/json",
                digest="sha256:2222222222222222222222222222222222222222222222222222222222222222",
                size=10,
            ),
            layers=[],
        ),
        config=None,
        layers_compressed_digests=[],
        layers_uncompressed_diff_ids=[],
        raw_blobs={},
    )

    reports = verifier.verify_oci_image_signatures(
        normalized_image=norm_img,
        trust_material=VerificationTrustMaterial(),
    )

    assert len(reports) == 1
    assert reports[0].status == "COSIGN_REFERRER_MISSING"
