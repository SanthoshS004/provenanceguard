"""
Unit Tests for Artifact Abstraction Models
"""

from provenanceguard.core.artifacts.models import Artifact, MediaType, VerificationStatus


def test_artifact_instantiation():
    artifact = Artifact(
        id="art_123",
        project_id="proj_456",
        name="payment-service",
        version="1.0.0",
        media_type=MediaType.ELF,
        digest_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        size_bytes=1024567,
    )

    assert artifact.id == "art_123"
    assert artifact.media_type == MediaType.ELF
    assert artifact.verification_status == VerificationStatus.UNVERIFIED
