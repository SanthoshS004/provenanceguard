"""
Unit Tests for Sigstore Bundle Verifier, Fulcio X.509 Path Validation
& RFC 8785 JCS Rekor SET Verification.
"""

import base64
import datetime
from datetime import timezone

import pytest
import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from provenanceguard.core.verification.dsse import compute_dsse_pae
from provenanceguard.core.verification.exceptions import SigstoreVerificationError
from provenanceguard.core.verification.sigstore import (
    MAX_BUNDLE_SIZE,
    MAX_CERT_CHAIN_LENGTH,
    SigstoreVerifier,
)
from provenanceguard.core.verification.trust import (
    VerificationAlgorithm,
    VerificationContext,
    VerificationKey,
    VerificationTrustMaterial,
)


@pytest.fixture
def fulcio_pki_fixture():
    """Generate self-signed Fulcio root CA, intermediate CA, and leaf certificate."""
    # Root CA
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fulcio Root CA")])
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

    # Intermediate CA
    int_key = ec.generate_private_key(ec.SECP256R1())
    int_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fulcio Intermediate CA")])
    int_cert = (
        x509.CertificateBuilder()
        .subject_name(int_name)
        .issuer_name(root_name)
        .public_key(int_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime.datetime(2030, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(root_key, hashes.SHA256())
    )

    # Leaf Certificate
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fulcio Leaf Cert")])

    # Extensions: SAN URIs and EKU Code Signing
    san_ext = x509.SubjectAlternativeName(
        [
            x509.UniformResourceIdentifier(
                "https://github.com/example/workflow/.github/workflows/build.yml@refs/heads/main"
            ),
            x509.UniformResourceIdentifier("https://example.com/publisher"),
        ]
    )
    eku_ext = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING])
    oidc_issuer_ext = x509.Extension(
        oid=x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1"),
        critical=False,
        value=x509.UnrecognizedExtension(
            oid=x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1"),
            value=b"https://token.actions.githubusercontent.com",
        ),
    )

    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(int_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime.datetime(2026, 12, 31, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(san_ext, critical=False)
        .add_extension(eku_ext, critical=True)
        .add_extension(oidc_issuer_ext.value, critical=False)
        .sign(int_key, hashes.SHA256())
    )

    return {
        "root_cert": root_cert,
        "int_cert": int_cert,
        "leaf_cert": leaf_cert,
        "leaf_key": leaf_key,
    }


@pytest.fixture
def rekor_key_fixture():
    rekor_priv = ec.generate_private_key(ec.SECP256R1())
    rekor_pub = rekor_priv.public_key()
    rekor_log_id = "a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0"
    vkey = VerificationKey(
        key_id=rekor_log_id,
        algorithm=VerificationAlgorithm.ECDSA_P256_SHA256,
        public_key=rekor_pub,
    )
    return rekor_priv, rekor_log_id, vkey


def test_rfc8785_jcs_conformance():
    """Verify RFC 8785 JCS canonicalization conformance."""
    data = {
        "b": 1,
        "a": 'test string with \\ and "',
        "nested": {"z": [3, 2, 1], "y": None, "x": True},
    }
    canonical_bytes = rfc8785.dumps(data)
    expected = (
        b'{"a":"test string with \\\\ and \\"","b":1,"nested":{"x":true,"y":null,"z":[3,2,1]}}'
    )
    assert canonical_bytes == expected


def test_sigstore_valid_bundle_verification(fulcio_pki_fixture, rekor_key_fixture):
    leaf_key = fulcio_pki_fixture["leaf_key"]
    leaf_cert = fulcio_pki_fixture["leaf_cert"]
    int_cert = fulcio_pki_fixture["int_cert"]
    root_cert = fulcio_pki_fixture["root_cert"]
    rekor_priv, rekor_log_id, rekor_vkey = rekor_key_fixture

    # Build DSSE Envelope signed by leaf_key
    payload_bytes = b'{"payload":"test_provenance"}'
    pae_bytes = compute_dsse_pae("application/vnd.in-toto+json", payload_bytes)
    sig_bytes = leaf_key.sign(pae_bytes, ec.ECDSA(hashes.SHA256()))

    dsse_envelope = {
        "payload": base64.b64encode(payload_bytes).decode("ascii"),
        "payloadType": "application/vnd.in-toto+json",
        "signatures": [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
    }

    # Prepare Rekor SET entry & RFC 8785 canonical signature
    entry_data = {
        "body": base64.b64encode(b'{"kind":"hashedrekord"}').decode("ascii"),
        "integratedTime": 1770000000,
        "logID": {"keyId": rekor_log_id},
        "logIndex": 42,
    }
    jcs_bytes = rfc8785.dumps(entry_data)
    rekor_sig = rekor_priv.sign(jcs_bytes, ec.ECDSA(hashes.SHA256()))
    rekor_sig_b64 = base64.b64encode(rekor_sig).decode("ascii")

    entry_data["verification"] = {
        "signedEntryTimestamp": rekor_sig_b64,
    }

    # Build Sigstore Bundle v0.3
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {
                        "rawBytes": base64.b64encode(
                            leaf_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    },
                    {
                        "rawBytes": base64.b64encode(
                            int_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    },
                ]
            },
            "tlogEntries": [entry_data],
        },
        "dsseEnvelope": dsse_envelope,
    }

    trust = VerificationTrustMaterial(
        fulcio_root_certificates=[root_cert],
        rekor_verification_keys={rekor_log_id: rekor_vkey},
    )

    ctx = VerificationContext(evaluation_time=datetime.datetime(2026, 6, 1, tzinfo=timezone.utc))

    verifier = SigstoreVerifier()
    report = verifier.verify_bundle(bundle, trust, ctx)

    assert report.certificate_chain_valid is True
    assert report.signature_verified is True
    assert report.certificate_time_valid is True
    assert report.time_validity_state == "EVALUATION_TIME_VALID"
    assert report.rekor_set_verified is True
    assert report.rekor_integrated_time_cryptographically_verified is True
    assert report.signing_time_evidence.verification_state == "CRYPTOGRAPHICALLY_VERIFIED"
    assert report.signing_time_evidence.timestamp == 1770000000
    assert len(report.san_uris_observed) == 2
    assert "https://example.com/publisher" in report.san_uris_observed


def test_sigstore_unconfigured_root_rejected(fulcio_pki_fixture):
    leaf_key = fulcio_pki_fixture["leaf_key"]
    leaf_cert = fulcio_pki_fixture["leaf_cert"]
    int_cert = fulcio_pki_fixture["int_cert"]

    payload_bytes = b"test"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
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
                    },
                    {
                        "rawBytes": base64.b64encode(
                            int_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    },
                ]
            }
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payloadType": "text/plain",
            "signatures": [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
        },
    }

    # Wrong root certificate configured
    wrong_root_key = ec.generate_private_key(ec.SECP256R1())
    wrong_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Wrong Root CA")])
    wrong_root_cert = (
        x509.CertificateBuilder()
        .subject_name(wrong_name)
        .issuer_name(wrong_name)
        .public_key(wrong_root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=timezone.utc))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=timezone.utc))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(wrong_root_key, hashes.SHA256())
    )

    trust = VerificationTrustMaterial(fulcio_root_certificates=[wrong_root_cert])
    verifier = SigstoreVerifier()

    with pytest.raises(SigstoreVerificationError) as exc:
        verifier.verify_bundle(bundle, trust)
    assert "Fulcio X.509 certificate path validation failed" in str(exc.value)


def test_sigstore_dsse_cardinality_rejection(fulcio_pki_fixture):
    leaf_cert = fulcio_pki_fixture["leaf_cert"]
    root_cert = fulcio_pki_fixture["root_cert"]

    # Multi-sig envelope inside Sigstore bundle -> Must be rejected (exactly 1 required)
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
            "payload": "dGVzdA==",
            "payloadType": "text/plain",
            "signatures": [{"sig": "aaaa"}, {"sig": "bbbb"}],
        },
    }

    trust = VerificationTrustMaterial(fulcio_root_certificates=[root_cert])
    verifier = SigstoreVerifier()

    with pytest.raises(SigstoreVerificationError) as exc:
        verifier.verify_bundle(bundle, trust)
    assert "MUST contain exactly 1 signature" in str(exc.value)


def test_sigstore_rekor_inclusion_proof_log_index_mismatch(fulcio_pki_fixture):
    leaf_key = fulcio_pki_fixture["leaf_key"]
    leaf_cert = fulcio_pki_fixture["leaf_cert"]
    int_cert = fulcio_pki_fixture["int_cert"]
    root_cert = fulcio_pki_fixture["root_cert"]

    payload_bytes = b"test"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
    sig_bytes = leaf_key.sign(pae_bytes, ec.ECDSA(hashes.SHA256()))

    entry_data = {
        "logIndex": 100,
        "verification": {
            "inclusionProof": {
                "logIndex": 200,  # Log index mismatch!
                "treeSize": 500,
                "rootHash": "aaaa",
                "hashes": ["bbbb"],
            }
        },
    }

    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "x509CertificateChain": {
                "certificates": [
                    {
                        "rawBytes": base64.b64encode(
                            leaf_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    },
                    {
                        "rawBytes": base64.b64encode(
                            int_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    },
                ]
            },
            "tlogEntries": [entry_data],
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payloadType": "text/plain",
            "signatures": [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
        },
    }

    trust = VerificationTrustMaterial(fulcio_root_certificates=[root_cert])
    verifier = SigstoreVerifier()

    with pytest.raises(SigstoreVerificationError) as exc:
        verifier.verify_bundle(bundle, trust)
    assert "logIndex (200) does not match entry logIndex (100)" in str(exc.value)


def test_sigstore_deterministic_certificate_time_evaluation(fulcio_pki_fixture):
    leaf_key = fulcio_pki_fixture["leaf_key"]
    leaf_cert = fulcio_pki_fixture["leaf_cert"]
    int_cert = fulcio_pki_fixture["int_cert"]
    root_cert = fulcio_pki_fixture["root_cert"]

    payload_bytes = b"test"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
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
                    },
                    {
                        "rawBytes": base64.b64encode(
                            int_cert.public_bytes(serialization.Encoding.DER)
                        ).decode("ascii")
                    },
                ]
            }
        },
        "dsseEnvelope": {
            "payload": base64.b64encode(payload_bytes).decode("ascii"),
            "payloadType": "text/plain",
            "signatures": [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
        },
    }

    trust = VerificationTrustMaterial(fulcio_root_certificates=[root_cert])
    verifier = SigstoreVerifier()

    # Evaluation time within cert validity window (2026-06-01)
    ctx_valid = VerificationContext(
        evaluation_time=datetime.datetime(2026, 6, 1, tzinfo=timezone.utc)
    )
    report_valid = verifier.verify_bundle(bundle, trust, ctx_valid)
    assert report_valid.certificate_time_valid is True
    assert report_valid.time_validity_state == "EVALUATION_TIME_VALID"

    # Evaluation time OUTSIDE cert validity window (2027-01-01) without verified SET
    ctx_expired = VerificationContext(
        evaluation_time=datetime.datetime(2027, 1, 1, tzinfo=timezone.utc)
    )
    report_expired = verifier.verify_bundle(bundle, trust, ctx_expired)
    assert report_expired.certificate_time_valid is False
    assert report_expired.time_validity_state == "INVALID"


def test_sigstore_resource_limit_bundle_size_boundary(fulcio_pki_fixture):
    verifier = SigstoreVerifier()
    trust = VerificationTrustMaterial(fulcio_root_certificates=[fulcio_pki_fixture["root_cert"]])

    # Bundle size > MAX_BUNDLE_SIZE (5 MB + 1 byte) -> rejected
    over_bundle_bytes = b"x" * (MAX_BUNDLE_SIZE + 1)
    with pytest.raises(SigstoreVerificationError) as exc:
        verifier.verify_bundle(over_bundle_bytes, trust)
    assert "exceeds limit" in str(exc.value)


def test_sigstore_resource_limit_cert_chain_length_boundary(fulcio_pki_fixture):
    leaf_cert = fulcio_pki_fixture["leaf_cert"]
    root_cert = fulcio_pki_fixture["root_cert"]
    verifier = SigstoreVerifier()
    trust = VerificationTrustMaterial(fulcio_root_certificates=[root_cert])

    cert_raw = base64.b64encode(leaf_cert.public_bytes(serialization.Encoding.DER)).decode("ascii")

    # Limit + 1 (11 certificates in chain) -> rejected
    chain_over = [{"rawBytes": cert_raw} for _ in range(MAX_CERT_CHAIN_LENGTH + 1)]
    bundle_over = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"x509CertificateChain": {"certificates": chain_over}},
        "dsseEnvelope": {
            "payload": "dGVzdA==",
            "payloadType": "text/plain",
            "signatures": [{"sig": "aaaa"}],
        },
    }
    with pytest.raises(SigstoreVerificationError) as exc:
        verifier.verify_bundle(bundle_over, trust)
    assert "certificate chain length" in str(exc.value) and "exceeds limit" in str(exc.value)
