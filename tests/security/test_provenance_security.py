"""
Security Boundary Tests for Phase 5 Attestation Verification & Provenance Engine.
"""

import base64
import datetime
from datetime import timezone
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from provenanceguard.core.verification.dsse import DSSEVerifier, compute_dsse_pae
from provenanceguard.core.verification.provenance import SLSAProvenanceValidator
from provenanceguard.core.verification.provenance_models import (
    CombinedAttestationVerificationReport,
)
from provenanceguard.core.verification.sigstore import SigstoreVerifier
from provenanceguard.core.verification.trust import (
    VerificationAlgorithm,
    VerificationContext,
    VerificationKey,
    VerificationTrustMaterial,
)


@pytest.fixture
def sample_verification_setup():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root CA")])
    root_cert = (
        x509.CertificateBuilder()
        .subject_name(root_name)
        .issuer_name(root_name)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Leaf Cert")])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(root_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime.datetime(2026, 12, 31, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    payload_bytes = b'{"_type":"https://in-toto.io/Statement/v1","subject":[],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"buildDefinition":{"buildType":"test"},"runDetails":{"builder":{}}}}'
    pae_bytes = compute_dsse_pae("application/vnd.in-toto+json", payload_bytes)
    sig_bytes = leaf_key.sign(pae_bytes, ec.ECDSA(hashes.SHA256()))

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {
                        "rawBytes": base64.b64encode(
                            leaf_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    }
                ]
            }
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
        },
    }

    ver_key = VerificationKey(
        key_id="leaf_key",
        algorithm=VerificationAlgorithm.ECDSA_P256_SHA256,
        public_key=leaf_key.public_key(),
    )
    trust = VerificationTrustMaterial(
        dsse_public_keys={"leaf_key": ver_key},
        fulcio_root_certificates=[root_cert],
    )
    return bundle, trust, payload_bytes


def test_evidence_boundary_no_policy_verdicts(sample_verification_setup):
    bundle, trust, payload_bytes = sample_verification_setup
    ctx = VerificationContext(evaluation_time=datetime.datetime(2026, 6, 1, tzinfo=timezone.utc))

    dsse_verifier = DSSEVerifier()
    dsse_report = dsse_verifier.verify_envelope(bundle["dsseEnvelope"], trust)

    slsa_validator = SLSAProvenanceValidator()
    slsa_report = slsa_validator.validate_statement(payload_bytes)

    sigstore_verifier = SigstoreVerifier()
    sigstore_report = sigstore_verifier.verify_bundle(bundle, trust, ctx)

    combined = CombinedAttestationVerificationReport(
        dsse_report=dsse_report,
        slsa_report=slsa_report,
        sigstore_report=sigstore_report,
    )

    combined_dict = combined.model_dump()
    forbidden_terms = [
        "PASS",
        "BLOCK",
        "risk_score",
        "risk_level",
        "trust_status",
        "trusted",
        "untrusted",
    ]

    dict_str = str(combined_dict)
    for term in forbidden_terms:
        assert term not in dict_str, (
            f"Forbidden policy/verdict term '{term}' found in evidence report"
        )


def test_zero_subprocess_boundary(sample_verification_setup):
    bundle, trust, payload_bytes = sample_verification_setup
    ctx = VerificationContext(evaluation_time=datetime.datetime(2026, 6, 1, tzinfo=timezone.utc))

    with patch("subprocess.Popen", side_effect=RuntimeError("Subprocess call forbidden")):
        with patch("subprocess.run", side_effect=RuntimeError("Subprocess call forbidden")):
            sigstore_verifier = SigstoreVerifier()
            report = sigstore_verifier.verify_bundle(bundle, trust, ctx)
            assert report.signature_verified is True
