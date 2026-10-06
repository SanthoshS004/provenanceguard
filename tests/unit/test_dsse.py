"""
Unit Tests for DSSE Verifier & Exact-Byte PAE.
"""

import base64
import hashlib
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from provenanceguard.core.verification.dsse import (
    MAX_DSSE_ENVELOPE_SIZE,
    MAX_DSSE_PAYLOAD_SIZE,
    MAX_DSSE_PAYLOAD_TYPE_SIZE,
    MAX_DSSE_SIGNATURE_COUNT,
    MAX_DSSE_SIGNATURE_SIZE,
    DSSEVerifier,
    compute_dsse_pae,
)
from provenanceguard.core.verification.exceptions import DSSEVerificationError
from provenanceguard.core.verification.trust import (
    VerificationAlgorithm,
    VerificationKey,
    VerificationTrustMaterial,
)


@pytest.fixture
def keys_fixture():
    """Generate cryptographic keys for DSSE test suite."""
    ed_priv = ed25519.Ed25519PrivateKey.generate()
    ed_pub = ed_priv.public_key()

    ec_priv = ec.generate_private_key(ec.SECP256R1())
    ec_pub = ec_priv.public_key()

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()

    return {
        "ed": (
            ed_priv,
            VerificationKey(
                key_id="ed_key_1",
                algorithm=VerificationAlgorithm.ED25519,
                public_key=ed_pub,
            ),
        ),
        "ec": (
            ec_priv,
            VerificationKey(
                key_id="ec_key_1",
                algorithm=VerificationAlgorithm.ECDSA_P256_SHA256,
                public_key=ec_pub,
            ),
        ),
        "rsa_pss": (
            rsa_priv,
            VerificationKey(
                key_id="rsa_pss_key_1",
                algorithm=VerificationAlgorithm.RSA_PSS_SHA256,
                public_key=rsa_pub,
            ),
        ),
        "rsa_pkcs1": (
            rsa_priv,
            VerificationKey(
                key_id="rsa_pkcs1_key_1",
                algorithm=VerificationAlgorithm.RSA_PKCS1_SHA256,
                public_key=rsa_pub,
            ),
        ),
    }


def make_envelope(
    payload_str: str,
    payload_type: str,
    signatures: list,
) -> dict:
    payload_b64 = base64.b64encode(payload_str.encode("utf-8")).decode("ascii")
    return {
        "payload": payload_b64,
        "payloadType": payload_type,
        "signatures": signatures,
    }


def sign_pae(priv_key, algorithm: VerificationAlgorithm, pae_bytes: bytes) -> bytes:
    if algorithm == VerificationAlgorithm.ED25519:
        return priv_key.sign(pae_bytes)
    elif algorithm == VerificationAlgorithm.ECDSA_P256_SHA256:
        return priv_key.sign(pae_bytes, ec.ECDSA(hashes.SHA256()))
    elif algorithm == VerificationAlgorithm.RSA_PSS_SHA256:
        return priv_key.sign(
            pae_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    elif algorithm == VerificationAlgorithm.RSA_PKCS1_SHA256:
        return priv_key.sign(pae_bytes, padding.PKCS1v15(), hashes.SHA256())
    raise ValueError("Unsupported algorithm")


def test_exact_byte_pae_computation():
    pae = compute_dsse_pae("application/vnd.in-toto+json", b'{"test":1}')
    expected = b'DSSEv1 28 application/vnd.in-toto+json 10 {"test":1}'
    assert pae == expected


def test_dsse_matching_key_id_ed25519(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    payload_bytes = b'{"statement":"slsa"}'
    pae_bytes = compute_dsse_pae("application/vnd.in-toto+json", payload_bytes)
    sig_bytes = sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)
    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

    envelope = make_envelope(
        payload_bytes.decode("utf-8"),
        "application/vnd.in-toto+json",
        [{"keyid": "ed_key_1", "sig": sig_b64}],
    )

    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})
    verifier = DSSEVerifier()
    report = verifier.verify_envelope(envelope, trust)

    assert report.signature_verified is True
    assert report.signatures_verified == 1
    assert report.key_ids_verified == ["ed_key_1"]
    assert report.payload_type == "application/vnd.in-toto+json"
    assert report.payload_sha256 == hashlib.sha256(payload_bytes).hexdigest()


def test_dsse_algorithm_profiles_ecdsa_rsa(keys_fixture):
    ec_priv, ec_vkey = keys_fixture["ec"]
    rsa_priv, rsa_vkey = keys_fixture["rsa_pss"]

    payload_bytes = b"sample_payload"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)

    sig_ec = sign_pae(ec_priv, VerificationAlgorithm.ECDSA_P256_SHA256, pae_bytes)
    sig_rsa = sign_pae(rsa_priv, VerificationAlgorithm.RSA_PSS_SHA256, pae_bytes)

    envelope = make_envelope(
        "sample_payload",
        "text/plain",
        [
            {"keyid": "ec_key_1", "sig": base64.b64encode(sig_ec).decode("ascii")},
            {"keyid": "rsa_pss_key_1", "sig": base64.b64encode(sig_rsa).decode("ascii")},
        ],
    )

    trust = VerificationTrustMaterial(
        dsse_public_keys={"ec_key_1": ec_vkey, "rsa_pss_key_1": rsa_vkey}
    )
    verifier = DSSEVerifier()
    report = verifier.verify_envelope(envelope, trust)

    assert report.signature_verified is True
    assert report.signatures_verified == 2
    assert report.key_ids_verified == ["ec_key_1", "rsa_pss_key_1"]


def test_dsse_absent_key_id_exactly_one_candidate(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    payload_bytes = b"test_payload"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
    sig_bytes = sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)

    envelope = make_envelope(
        "test_payload",
        "text/plain",
        [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
    )

    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})
    verifier = DSSEVerifier()
    report = verifier.verify_envelope(envelope, trust)

    assert report.signature_verified is True
    assert report.signatures_verified == 1
    assert report.key_ids_verified == ["ed_key_1"]
    assert any("absent" in w for w in report.warnings)


def test_dsse_absent_key_id_zero_candidates(keys_fixture):
    ed_priv, _ = keys_fixture["ed"]
    payload_bytes = b"test_payload"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
    sig_bytes = sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)

    envelope = make_envelope(
        "test_payload",
        "text/plain",
        [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
    )

    # Trust material has a key that does NOT match the signature
    other_priv = ed25519.Ed25519PrivateKey.generate()
    other_vkey = VerificationKey(
        key_id="other_key",
        algorithm=VerificationAlgorithm.ED25519,
        public_key=other_priv.public_key(),
    )

    trust = VerificationTrustMaterial(dsse_public_keys={"other_key": other_vkey})
    verifier = DSSEVerifier()

    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(envelope, trust)
    assert "PG-5001" in str(exc.value)


def test_dsse_absent_key_id_multiple_candidates(keys_fixture):
    # Two candidate keys where BOTH happen to verify (e.g. duplicate key injected)
    ed_priv, ed_vkey = keys_fixture["ed"]
    ed_vkey_dupe = VerificationKey(
        key_id="ed_key_2",
        algorithm=VerificationAlgorithm.ED25519,
        public_key=ed_vkey.public_key,
    )

    payload_bytes = b"test_payload"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
    sig_bytes = sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)

    envelope = make_envelope(
        "test_payload",
        "text/plain",
        [{"sig": base64.b64encode(sig_bytes).decode("ascii")}],
    )

    trust = VerificationTrustMaterial(
        dsse_public_keys={"ed_key_1": ed_vkey, "ed_key_2": ed_vkey_dupe}
    )
    verifier = DSSEVerifier()

    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(envelope, trust)
    assert "Ambiguous DSSE key-ID" in str(exc.value)


def test_dsse_unknown_key_id(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    payload_bytes = b"test"
    pae_bytes = compute_dsse_pae("text/plain", payload_bytes)
    sig_bytes = sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)

    envelope = make_envelope(
        "test",
        "text/plain",
        [{"keyid": "non_existent_key", "sig": base64.b64encode(sig_bytes).decode("ascii")}],
    )

    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})
    verifier = DSSEVerifier()

    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(envelope, trust)
    assert "Unknown DSSE signature keyid" in str(exc.value)


def test_dsse_invalid_signature_bytes(keys_fixture):
    _, ed_vkey = keys_fixture["ed"]
    bad_sig = base64.b64encode(b"0" * 64).decode("ascii")

    envelope = make_envelope(
        "test",
        "text/plain",
        [{"keyid": "ed_key_1", "sig": bad_sig}],
    )

    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})
    verifier = DSSEVerifier()

    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(envelope, trust)
    assert "Invalid DSSE signature" in str(exc.value)


def test_dsse_resource_limit_envelope_size_boundary(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    pae_bytes = compute_dsse_pae("text/plain", b"test")
    sig_b64 = base64.b64encode(sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)).decode(
        "ascii"
    )

    # Limit + 1 byte -> rejected
    large_payload_over = "x" * (MAX_DSSE_ENVELOPE_SIZE + 1)
    env_over = make_envelope(
        large_payload_over, "text/plain", [{"keyid": "ed_key_1", "sig": sig_b64}]
    )
    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})
    verifier = DSSEVerifier()

    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(json.dumps(env_over), trust)
    assert "exceeds limit" in str(exc.value)


def test_dsse_resource_limit_payload_size_boundary(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    verifier = DSSEVerifier()
    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})

    # Exact limit (1 MB decoded payload) -> accepted
    exact_payload = b"a" * MAX_DSSE_PAYLOAD_SIZE
    pae_exact = compute_dsse_pae("text/plain", exact_payload)
    sig_exact = base64.b64encode(
        sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_exact)
    ).decode("ascii")
    env_exact = {
        "payload": base64.b64encode(exact_payload).decode("ascii"),
        "payloadType": "text/plain",
        "signatures": [{"keyid": "ed_key_1", "sig": sig_exact}],
    }
    report = verifier.verify_envelope(env_exact, trust)
    assert report.signature_verified is True
    assert report.decoded_payload_size == MAX_DSSE_PAYLOAD_SIZE

    # Limit + 1 byte (1 MB + 1 byte decoded payload) -> rejected
    over_payload = b"a" * (MAX_DSSE_PAYLOAD_SIZE + 1)
    pae_over = compute_dsse_pae("text/plain", over_payload)
    sig_over = base64.b64encode(sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_over)).decode(
        "ascii"
    )
    env_over = {
        "payload": base64.b64encode(over_payload).decode("ascii"),
        "payloadType": "text/plain",
        "signatures": [{"keyid": "ed_key_1", "sig": sig_over}],
    }
    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(env_over, trust)
    assert "decoded payload size" in str(exc.value) and "exceeds limit" in str(exc.value)


def test_dsse_resource_limit_payload_type_size_boundary(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    verifier = DSSEVerifier()
    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})

    # Exact limit (256 bytes) -> accepted
    exact_type = "a" * MAX_DSSE_PAYLOAD_TYPE_SIZE
    pae_exact = compute_dsse_pae(exact_type, b"test")
    sig_exact = base64.b64encode(
        sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_exact)
    ).decode("ascii")
    env_exact = make_envelope("test", exact_type, [{"keyid": "ed_key_1", "sig": sig_exact}])
    report = verifier.verify_envelope(env_exact, trust)
    assert report.signature_verified is True

    # Limit + 1 (257 bytes) -> rejected
    huge_type = "a" * (MAX_DSSE_PAYLOAD_TYPE_SIZE + 1)
    env_over = make_envelope("test", huge_type, [{"keyid": "ed_key_1", "sig": "aaaa"}])
    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(env_over, trust)
    assert "payloadType length exceeds limit" in str(exc.value)


def test_dsse_resource_limit_signature_count_boundary(keys_fixture):
    ed_priv, ed_vkey = keys_fixture["ed"]
    verifier = DSSEVerifier()
    trust = VerificationTrustMaterial(dsse_public_keys={"ed_key_1": ed_vkey})

    # Exact limit (32 signatures) -> accepted
    pae_bytes = compute_dsse_pae("text/plain", b"test")
    sig_b64 = base64.b64encode(sign_pae(ed_priv, VerificationAlgorithm.ED25519, pae_bytes)).decode(
        "ascii"
    )
    sigs_exact = [{"keyid": "ed_key_1", "sig": sig_b64} for _ in range(MAX_DSSE_SIGNATURE_COUNT)]
    env_exact = make_envelope("test", "text/plain", sigs_exact)
    report = verifier.verify_envelope(env_exact, trust)
    assert report.signatures_observed == MAX_DSSE_SIGNATURE_COUNT

    # Limit + 1 (33 signatures) -> rejected
    sigs_over = [{"keyid": f"k_{i}", "sig": "aaaa"} for i in range(MAX_DSSE_SIGNATURE_COUNT + 1)]
    env_over = make_envelope("test", "text/plain", sigs_over)
    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(env_over, trust)
    assert "signature count" in str(exc.value) and "exceeds limit" in str(exc.value)


def test_dsse_resource_limit_signature_size_boundary(keys_fixture):
    verifier = DSSEVerifier()
    trust = VerificationTrustMaterial()

    # Limit + 1 byte (4097 bytes decoded signature) -> rejected
    huge_sig_bytes = b"s" * (MAX_DSSE_SIGNATURE_SIZE + 1)
    huge_sig_b64 = base64.b64encode(huge_sig_bytes).decode("ascii")
    env_over = make_envelope("test", "text/plain", [{"keyid": "k1", "sig": huge_sig_b64}])
    with pytest.raises(DSSEVerificationError) as exc:
        verifier.verify_envelope(env_over, trust)
    assert "signature size" in str(exc.value) and "exceeds limit" in str(exc.value)
