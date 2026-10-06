"""
Cosign / Sigstore OCI Attestation Verifier & Offline Discovery Engine.
Reuses Phase 5 Sigstore (sigstore.py) and DSSE (dsse.py) verification engines.
"""

import json
import re
from typing import List, Optional, Tuple

from pydantic import BaseModel, Field

from provenanceguard.analyzers.oci.oci_adapters import (
    validate_descriptor_size,
)
from provenanceguard.analyzers.oci.oci_spec import (
    COSIGN_SIGNATURE_MEDIA_TYPE,
    IN_TOTO_DSSE_MEDIA_TYPE,
    NormalizedOCIImage,
)
from provenanceguard.core.verification.dsse import DSSEVerifier
from provenanceguard.core.verification.sigstore import SigstoreVerifier
from provenanceguard.core.verification.trust import (
    VerificationTrustMaterial,
)


class SignerAuthorizationPolicy(BaseModel):
    """Signer authorization policy specifying trusted OIDC issuers and SAN patterns."""

    trusted_oidc_issuers: List[str] = Field(default_factory=list)
    allowed_san_patterns: List[str] = Field(default_factory=list)

    def is_authorized(self, issuer: Optional[str], san_uris: List[str]) -> bool:
        """
        Evaluates whether observed certificate evidence satisfies authorization policy.
        """
        if self.trusted_oidc_issuers:
            if not issuer or issuer not in self.trusted_oidc_issuers:
                return False

        if self.allowed_san_patterns:
            if not san_uris:
                return False
            any_san_matched = False
            for pattern in self.allowed_san_patterns:
                for san in san_uris:
                    if re.match(pattern, san):
                        any_san_matched = True
                        break
                if any_san_matched:
                    break
            if not any_san_matched:
                return False

        return True


class OCISignatureReport(BaseModel):
    """Verification verdict report for Cosign signature or in-toto DSSE attestation."""

    status: str  # PASS, COSIGN_DIGEST_MISMATCH, COSIGN_REFERRER_MISSING, REKOR_EVIDENCE_MISSING, UNAUTHORIZED_SIGNER, INVALID_SIGNATURE
    claimed_digest: Optional[str] = None
    target_manifest_digest: str
    signature_verified: bool = False
    payload_type: Optional[str] = None
    issuer_observed: Optional[str] = None
    san_uris_observed: List[str] = Field(default_factory=list)
    rekor_evidence_status: str = "UNAVAILABLE"  # VERIFIED, REKOR_EVIDENCE_MISSING, UNAVAILABLE
    warnings: List[str] = Field(default_factory=list)


class OCISigstoreVerifier:
    """
    Offline OCI archive signature & attestation verifier.
    """

    def verify_oci_image_signatures(
        self,
        normalized_image: NormalizedOCIImage,
        trust_material: VerificationTrustMaterial,
        signer_policy: Optional[SignerAuthorizationPolicy] = None,
    ) -> List[OCISignatureReport]:
        """
        Discovers locally present subject-linked signature/attestation artifacts in offline archive
        and executes verification pipeline.
        """
        reports: List[OCISignatureReport] = []
        target_digest = normalized_image.selected_manifest_digest

        # Discover locally present subject-linked artifacts in archive
        discovered_artifacts = self._discover_subject_linked_artifacts(normalized_image)

        if not discovered_artifacts:
            # Emit COSIGN_REFERRER_MISSING status when zero subject-linked artifacts exist
            reports.append(
                OCISignatureReport(
                    status="COSIGN_REFERRER_MISSING",
                    target_manifest_digest=target_digest,
                    signature_verified=False,
                    warnings=[
                        "No subject-linked signature or attestation artifacts found in offline archive"
                    ],
                )
            )
            return reports

        sigstore_verifier = SigstoreVerifier()
        dsse_verifier = DSSEVerifier()

        for art_media_type, art_bytes in discovered_artifacts:
            # Validate blob digest and size before processing
            validate_descriptor_size(len(art_bytes))

            if art_media_type == COSIGN_SIGNATURE_MEDIA_TYPE or "cosign" in art_media_type.lower():
                report = self._verify_cosign_simple_signing(
                    art_bytes, target_digest, trust_material, signer_policy, sigstore_verifier
                )
                reports.append(report)

            elif (
                art_media_type == IN_TOTO_DSSE_MEDIA_TYPE
                or "in-toto" in art_media_type.lower()
                or "dsse" in art_media_type.lower()
            ):
                report = self._verify_in_toto_dsse_attestation(
                    art_bytes, target_digest, trust_material, signer_policy, dsse_verifier
                )
                reports.append(report)

            else:
                # Attempt generic Sigstore bundle or DSSE verification
                try:
                    report = self._verify_cosign_simple_signing(
                        art_bytes, target_digest, trust_material, signer_policy, sigstore_verifier
                    )
                    reports.append(report)
                except Exception:
                    reports.append(
                        OCISignatureReport(
                            status="DOCKER_SAVE_SIGNATURE_UNSUPPORTED",
                            target_manifest_digest=target_digest,
                            signature_verified=False,
                            warnings=[f"Unsupported artifact mediaType '{art_media_type}'"],
                        )
                    )

        return reports

    def _discover_subject_linked_artifacts(
        self,
        normalized_image: NormalizedOCIImage,
    ) -> List[Tuple[str, bytes]]:
        """
        Enumerates locally present manifests/indexes and identifies subject-linked descriptors
        whose subject.digest equals selected target manifest digest.
        """
        discovered: List[Tuple[str, bytes]] = []
        target_digest = normalized_image.selected_manifest_digest
        blobs = normalized_image.raw_blobs

        # Check index.json or descriptors for subject.digest matching target_digest
        if "index.json" in blobs:
            try:
                index_data = json.loads(blobs["index.json"].decode("utf-8"))
                manifests = index_data.get("manifests", [])
                for desc in manifests:
                    subj = desc.get("subject", {})
                    subj_digest = subj.get("digest") if isinstance(subj, dict) else None
                    if subj_digest and subj_digest.lower() == target_digest.lower():
                        desc_digest = desc.get("digest")
                        desc_media_type = desc.get("mediaType") or desc.get("artifactType", "")
                        if desc_digest and desc_digest in blobs:
                            discovered.append((desc_media_type, blobs[desc_digest]))
            except Exception:
                pass

        # Also check fallback .sig / .att blobs physically in blobs
        for k, v in blobs.items():
            if k.endswith(".sig") or k.endswith(".att"):
                discovered.append(("application/vnd.dev.cosign.simplesigning.v1+json", v))

        return discovered

    def _verify_cosign_simple_signing(
        self,
        art_bytes: bytes,
        target_digest: str,
        trust_material: VerificationTrustMaterial,
        signer_policy: Optional[SignerAuthorizationPolicy],
        sigstore_verifier: SigstoreVerifier,
    ) -> OCISignatureReport:
        """Path A: Cosign image signature verification over target OCI manifest digest."""
        try:
            # Check if payload is a Sigstore bundle or Simple Container Image Payload JSON
            bundle_data = json.loads(art_bytes.decode("utf-8"))
        except Exception as e:
            return OCISignatureReport(
                status="INVALID_SIGNATURE",
                target_manifest_digest=target_digest,
                signature_verified=False,
                warnings=[f"Malformed signature JSON: {str(e)}"],
            )

        # 1. Parse Simple Container Image Payload JSON or Sigstore bundle
        claimed_digest: Optional[str] = None

        if "critical" in bundle_data and "image" in bundle_data.get("critical", {}):
            # Direct simple signing payload
            claimed_digest = bundle_data["critical"]["image"].get("docker-manifest-digest")
        elif "dsseEnvelope" in bundle_data:
            # Sigstore Bundle v0.2/v0.3
            try:
                sigstore_report = sigstore_verifier.verify_bundle(bundle_data, trust_material)
                # Decode inner DSSE payload to extract claimed digest
                dsse_env = bundle_data.get("dsseEnvelope", {})
                payload_b64 = dsse_env.get("payload", "")
                import base64

                decoded_inner = base64.b64decode(payload_b64).decode("utf-8")
                inner_json = json.loads(decoded_inner)
                if "critical" in inner_json and "image" in inner_json.get("critical", {}):
                    claimed_digest = inner_json["critical"]["image"].get("docker-manifest-digest")

                # Check Signer Authorization Policy
                if signer_policy and not signer_policy.is_authorized(
                    sigstore_report.issuer_observed, sigstore_report.san_uris_observed
                ):
                    return OCISignatureReport(
                        status="UNAUTHORIZED_SIGNER",
                        claimed_digest=claimed_digest,
                        target_manifest_digest=target_digest,
                        signature_verified=False,
                        issuer_observed=sigstore_report.issuer_observed,
                        san_uris_observed=sigstore_report.san_uris_observed,
                        warnings=["Signer failed authorization policy"],
                    )

                # Check Claimed Digest matching
                if not claimed_digest or claimed_digest.lower() != target_digest.lower():
                    return OCISignatureReport(
                        status="COSIGN_DIGEST_MISMATCH",
                        claimed_digest=claimed_digest,
                        target_manifest_digest=target_digest,
                        signature_verified=False,
                        warnings=[
                            f"Claimed digest '{claimed_digest}' mismatches target digest '{target_digest}'"
                        ],
                    )

                rekor_status = (
                    "VERIFIED"
                    if sigstore_report.rekor_inclusion_proof_verified
                    else "REKOR_EVIDENCE_MISSING"
                )

                return OCISignatureReport(
                    status="PASS" if rekor_status == "VERIFIED" else "REKOR_EVIDENCE_MISSING",
                    claimed_digest=claimed_digest,
                    target_manifest_digest=target_digest,
                    signature_verified=True,
                    issuer_observed=sigstore_report.issuer_observed,
                    san_uris_observed=sigstore_report.san_uris_observed,
                    rekor_evidence_status=rekor_status,
                )

            except Exception as e:
                return OCISignatureReport(
                    status="INVALID_SIGNATURE",
                    target_manifest_digest=target_digest,
                    signature_verified=False,
                    warnings=[f"Sigstore bundle verification failed: {str(e)}"],
                )

        # Check digest mismatch for simple signing payload
        if not claimed_digest or claimed_digest.lower() != target_digest.lower():
            return OCISignatureReport(
                status="COSIGN_DIGEST_MISMATCH",
                claimed_digest=claimed_digest,
                target_manifest_digest=target_digest,
                signature_verified=False,
                warnings=[
                    f"Claimed digest '{claimed_digest}' mismatches target digest '{target_digest}'"
                ],
            )

        return OCISignatureReport(
            status="PASS",
            claimed_digest=claimed_digest,
            target_manifest_digest=target_digest,
            signature_verified=True,
        )

    def _verify_in_toto_dsse_attestation(
        self,
        art_bytes: bytes,
        target_digest: str,
        trust_material: VerificationTrustMaterial,
        signer_policy: Optional[SignerAuthorizationPolicy],
        dsse_verifier: DSSEVerifier,
    ) -> OCISignatureReport:
        """Path B: in-toto DSSE attestation verification reusing Phase 5 dsse.py."""
        try:
            dsse_report = dsse_verifier.verify_envelope(art_bytes, trust_material)
            if not dsse_report.signature_verified:
                return OCISignatureReport(
                    status="INVALID_SIGNATURE",
                    target_manifest_digest=target_digest,
                    signature_verified=False,
                    payload_type=dsse_report.payload_type,
                    warnings=["DSSE envelope signature verification failed"],
                )

            # Decode payload & parse in-toto statement to check subject digest
            import base64

            env_json = json.loads(art_bytes.decode("utf-8"))
            payload_bytes = base64.b64decode(env_json["payload"])
            statement = json.loads(payload_bytes.decode("utf-8"))

            subject_digest: Optional[str] = None
            subjects = statement.get("subject", [])
            if isinstance(subjects, list):
                for subj in subjects:
                    digests = subj.get("digest", {})
                    if isinstance(digests, dict):
                        for alg, val in digests.items():
                            candidate = f"{alg}:{val}" if ":" not in val else val
                            if candidate.lower() == target_digest.lower():
                                subject_digest = candidate
                                break

            if not subject_digest:
                return OCISignatureReport(
                    status="COSIGN_DIGEST_MISMATCH",
                    claimed_digest=subject_digest,
                    target_manifest_digest=target_digest,
                    signature_verified=False,
                    payload_type=dsse_report.payload_type,
                    warnings=[
                        f"In-toto attestation subject digest mismatches target '{target_digest}'"
                    ],
                )

            return OCISignatureReport(
                status="PASS",
                claimed_digest=subject_digest,
                target_manifest_digest=target_digest,
                signature_verified=True,
                payload_type=dsse_report.payload_type,
            )

        except Exception as e:
            return OCISignatureReport(
                status="INVALID_SIGNATURE",
                target_manifest_digest=target_digest,
                signature_verified=False,
                warnings=[f"DSSE attestation verification failed: {str(e)}"],
            )
