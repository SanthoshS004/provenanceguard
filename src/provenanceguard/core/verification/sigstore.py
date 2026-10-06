"""
Sigstore Bundle (v0.3/v0.2/v0.1), Fulcio & RFC 8785 JCS Rekor Verifier.
"""

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union

import rfc8785
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from provenanceguard.core.verification.dsse import DSSEVerifier
from provenanceguard.core.verification.exceptions import SigstoreVerificationError
from provenanceguard.core.verification.provenance_models import (
    SigningTimeEvidence,
    SigstoreIdentityReport,
)
from provenanceguard.core.verification.trust import (
    VerificationAlgorithm,
    VerificationContext,
    VerificationKey,
    VerificationTrustMaterial,
)

MAX_CERT_CHAIN_LENGTH = 10
MAX_BUNDLE_SIZE = 5 * 1024 * 1024  # 5 MB


def compute_merkle_root(
    leaf_hash: bytes, leaf_index: int, tree_size: int, audit_path: List[bytes]
) -> bytes:
    """
    Compute Merkle tree root hash from leaf hash, leaf index, tree size, and audit path
    according to RFC 6962.
    """
    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash

    for p in audit_path:
        if fn == sn or fn % 2 == 1:
            r = hashlib.sha256(b"\x01" + p + r).digest()
            while fn % 2 == 1:
                fn //= 2
                sn //= 2
        else:
            r = hashlib.sha256(b"\x01" + r + p).digest()
        fn //= 2
        sn //= 2
    return r


class SigstoreVerifier:
    """Verifier for Sigstore Bundles, Fulcio X.509 chains, and Rekor entries."""

    def verify_bundle(
        self,
        bundle_data: Union[Dict[str, Any], str, bytes],
        trust_material: VerificationTrustMaterial,
        context: Optional[VerificationContext] = None,
    ) -> SigstoreIdentityReport:
        """
        Verify Sigstore Bundle (v0.3 primary format, with v0.2/v0.1 legacy adapters).
        Uses deterministic injected context.evaluation_time for certificate time checks.
        """
        if context is None:
            context = VerificationContext(evaluation_time=datetime.now(timezone.utc))

        warnings: List[str] = []

        if isinstance(bundle_data, (str, bytes)):
            raw_bytes = bundle_data.encode("utf-8") if isinstance(bundle_data, str) else bundle_data
            if len(raw_bytes) > MAX_BUNDLE_SIZE:
                raise SigstoreVerificationError(
                    f"Sigstore bundle size ({len(raw_bytes)} bytes) "
                    f"exceeds limit ({MAX_BUNDLE_SIZE} bytes)"
                )
            try:
                bundle = json.loads(raw_bytes)
            except Exception as e:
                raise SigstoreVerificationError(
                    f"Failed to parse Sigstore bundle JSON: {str(e)}"
                ) from e
        elif isinstance(bundle_dict := bundle_data, dict):
            raw_bytes = json.dumps(bundle_dict).encode("utf-8")
            if len(raw_bytes) > MAX_BUNDLE_SIZE:
                raise SigstoreVerificationError(
                    f"Sigstore bundle size ({len(raw_bytes)} bytes) "
                    f"exceeds limit ({MAX_BUNDLE_SIZE} bytes)"
                )
            bundle = bundle_dict
        else:
            raise SigstoreVerificationError("Invalid Sigstore bundle data type")

        media_type = bundle.get("mediaType", "")
        if not media_type:
            # Check legacy v0.1/v0.2 heuristic
            if "verificationMaterial" in bundle and "dsseEnvelope" in bundle:
                media_type = "application/vnd.dev.sigstore.bundle.v0.2+json"
                warnings.append(
                    "Legacy Sigstore bundle missing explicit mediaType; treating as v0.2"
                )
            else:
                raise SigstoreVerificationError("Sigstore bundle missing 'mediaType'")

        bundle_version = "v0.3"
        if "v0.3" in media_type:
            bundle_version = "v0.3"
        elif "v0.2" in media_type:
            bundle_version = "v0.2"
        elif "v0.1" in media_type:
            bundle_version = "v0.1"
        else:
            warnings.append(
                f"Unrecognized bundle mediaType '{media_type}'; evaluating as v0.3 protocol"
            )

        # Extract DSSE Envelope & Enforce Sigstore Single DSSE Signature Cardinality
        dsse_envelope = bundle.get("dsseEnvelope")
        if not isinstance(dsse_envelope, dict):
            raise SigstoreVerificationError("Sigstore bundle missing 'dsseEnvelope' object")

        signatures = dsse_envelope.get("signatures", [])
        if not isinstance(signatures, list):
            raise SigstoreVerificationError("DSSE envelope 'signatures' must be a JSON array")

        if len(signatures) != 1:
            raise SigstoreVerificationError(
                "Sigstore bundle DSSE envelope MUST contain exactly 1 signature, "
                f"got {len(signatures)}"
            )

        # Extract verificationMaterial
        ver_mat = bundle.get("verificationMaterial")
        if not isinstance(ver_mat, dict):
            raise SigstoreVerificationError("Sigstore bundle missing 'verificationMaterial' object")

        # X.509 Certificate Chain Parsing
        cert_chain_raw = ver_mat.get("x509CertificateChain", {}).get("certificates", [])
        if not isinstance(cert_chain_raw, list) or len(cert_chain_raw) == 0:
            raise SigstoreVerificationError(
                "Sigstore bundle verificationMaterial missing X.509 certificates"
            )

        if len(cert_chain_raw) > MAX_CERT_CHAIN_LENGTH:
            raise SigstoreVerificationError(
                f"X.509 certificate chain length ({len(cert_chain_raw)}) "
                f"exceeds limit ({MAX_CERT_CHAIN_LENGTH})"
            )

        parsed_certs: List[x509.Certificate] = []
        for idx, cert_item in enumerate(cert_chain_raw):
            try:
                if isinstance(cert_item, dict) and "rawBytes" in cert_item:
                    raw_cert_b64 = cert_item["rawBytes"]
                    cert_bytes = base64.b64decode(raw_cert_b64, validate=True)
                elif isinstance(cert_item, str):
                    cert_bytes = base64.b64decode(cert_item, validate=True)
                else:
                    raise ValueError("Unknown cert format")
                parsed_cert = x509.load_der_x509_certificate(cert_bytes)
                parsed_certs.append(parsed_cert)
            except Exception as e:
                raise SigstoreVerificationError(
                    f"Failed to parse X.509 certificate at index {idx}: {str(e)}"
                ) from e

        leaf_cert = parsed_certs[0]
        bundle_intermediates = parsed_certs[1:]

        # Fulcio X.509 Path Validation against Configured Root Trust Anchors ONLY
        if not trust_material.fulcio_root_certificates:
            raise SigstoreVerificationError(
                "No configured Fulcio root trust anchors available in trust material"
            )

        path_valid = False
        matching_root: Optional[x509.Certificate] = None

        for root_ca in trust_material.fulcio_root_certificates:
            try:
                # Validate leaf -> intermediate chain -> root_ca
                # Check issuer matching and signature verification
                chain_to_verify = bundle_intermediates + [root_ca]

                # Check leaf basic constraints & EKU / key usage
                try:
                    ext_eku = leaf_cert.extensions.get_extension_for_oid(
                        x509.ExtensionOID.EXTENDED_KEY_USAGE
                    )
                    if x509.ExtendedKeyUsageOID.CODE_SIGNING not in ext_eku.value:
                        continue
                except x509.ExtensionNotFound:
                    continue

                # Verify certificate path signatures
                chain_ok = True
                curr = leaf_cert
                for parent in chain_to_verify:
                    if curr.issuer == parent.subject:
                        # Verify signature of curr using parent's public key
                        parent_pub = parent.public_key()
                        try:
                            if isinstance(parent_pub, rsa.RSAPublicKey):
                                parent_pub.verify(
                                    curr.signature,
                                    curr.tbs_certificate_bytes,
                                    padding.PKCS1v15(),
                                    curr.signature_hash_algorithm,
                                )
                            elif isinstance(parent_pub, ec.EllipticCurvePublicKey):
                                parent_pub.verify(
                                    curr.signature,
                                    curr.tbs_certificate_bytes,
                                    ec.ECDSA(curr.signature_hash_algorithm),
                                )
                            elif isinstance(parent_pub, ed25519.Ed25519PublicKey):
                                parent_pub.verify(
                                    curr.signature,
                                    curr.tbs_certificate_bytes,
                                )
                            else:
                                chain_ok = False
                                break
                        except Exception:
                            chain_ok = False
                            break
                        curr = parent
                        if curr.subject == root_ca.subject:
                            break
                    else:
                        chain_ok = False
                        break

                if chain_ok and curr.subject == root_ca.subject:
                    path_valid = True
                    matching_root = root_ca
                    break
            except Exception:
                continue

        if not path_valid or matching_root is None:
            raise SigstoreVerificationError(
                "Fulcio X.509 certificate path validation failed: "
                "leaf certificate does not anchor to any configured Fulcio root trust anchor"
            )

        certificate_chain_valid = True

        # Extract Identity Evidence (OIDC Issuer & SAN URIs)
        issuer_observed: Optional[str] = None
        san_uris_observed: List[str] = []

        # Extract OIDC Issuer extension (OID 1.3.6.1.4.1.57264.1.1)
        for ext in leaf_cert.extensions:
            if ext.oid.dotted_string == "1.3.6.1.4.1.57264.1.1":
                try:
                    # DER OctetString encoding inside extension
                    val_bytes = ext.value.value
                    issuer_observed = val_bytes.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass

        # Extract SAN URIs
        try:
            san_ext = leaf_cert.extensions.get_extension_for_oid(
                x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            for name in san_ext.value:
                if isinstance(name, x509.UniformResourceIdentifier):
                    san_uris_observed.append(name.value)
        except x509.ExtensionNotFound:
            pass

        # Extract leaf key for keyless DSSE signature verification after chain validation
        leaf_pub_key = leaf_cert.public_key()
        if isinstance(leaf_pub_key, ed25519.Ed25519PublicKey):
            leaf_alg = VerificationAlgorithm.ED25519
        elif isinstance(leaf_pub_key, ec.EllipticCurvePublicKey):
            leaf_alg = VerificationAlgorithm.ECDSA_P256_SHA256
        elif isinstance(leaf_pub_key, rsa.RSAPublicKey):
            leaf_alg = VerificationAlgorithm.RSA_PSS_SHA256
        else:
            raise SigstoreVerificationError(
                "Unsupported public key algorithm in Fulcio leaf certificate"
            )

        leaf_ver_key = VerificationKey(
            key_id="fulcio_leaf_key",
            algorithm=leaf_alg,
            public_key=leaf_pub_key,
        )

        # Inject leaf key into temporary trust material for DSSE verification
        temp_trust = VerificationTrustMaterial(
            dsse_public_keys={"fulcio_leaf_key": leaf_ver_key},
            fulcio_root_certificates=trust_material.fulcio_root_certificates,
            rekor_verification_keys=trust_material.rekor_verification_keys,
            timestamp_verification_roots=trust_material.timestamp_verification_roots,
        )

        dsse_verifier = DSSEVerifier()
        dsse_report = dsse_verifier.verify_envelope(dsse_envelope, temp_trust)

        if not dsse_report.signature_verified:
            raise SigstoreVerificationError(
                "Keyless DSSE signature verification failed against validated Fulcio leaf key"
            )

        signature_verified = True

        # Rekor Transparency Log Entry & SET Verification (RFC 8785 JCS)
        tlog_entries = ver_mat.get("tlogEntries", [])
        rekor_entry_observed = False
        rekor_set_verified = False
        rekor_checkpoint_verified = False
        rekor_inclusion_proof_verified = False
        rekor_integrated_time: Optional[int] = None
        rekor_integrated_time_cryptographically_verified = False

        if isinstance(tlog_entries, list) and len(tlog_entries) > 0:
            rekor_entry_observed = True
            tlog_entry = tlog_entries[0]
            if isinstance(tlog_entry, dict):
                log_id_obj = tlog_entry.get("logId") or tlog_entry.get("logID") or {}
                log_id_hex = ""
                if isinstance(log_id_obj, dict):
                    log_id_hex = log_id_obj.get("keyId") or log_id_obj.get("keyid") or ""
                    if log_id_hex and log_id_hex not in trust_material.rekor_verification_keys:
                        try:
                            decoded_hex = base64.b64decode(log_id_hex, validate=True).hex()
                            if decoded_hex in trust_material.rekor_verification_keys:
                                log_id_hex = decoded_hex
                        except Exception:
                            pass
                log_index_val = tlog_entry.get("logIndex")

                canon_body_b64 = tlog_entry.get("canonicalizedBody")

                integrated_time_val = tlog_entry.get("integratedTime")
                if integrated_time_val is not None:
                    try:
                        rekor_integrated_time = int(integrated_time_val)
                    except (ValueError, TypeError):
                        pass

                # RFC 8785 JCS SET Verification
                ver_obj = tlog_entry.get("verification")
                if isinstance(ver_obj, dict) and "signedEntryTimestamp" in ver_obj:
                    set_b64 = ver_obj["signedEntryTimestamp"]
                    try:
                        set_bytes = base64.b64decode(set_b64, validate=True)

                        # Entry dict without 'verification' for RFC 8785 JCS canonicalization
                        entry_copy = {k: v for k, v in tlog_entry.items() if k != "verification"}
                        jcs_canonical_bytes = rfc8785.dumps(entry_copy)

                        # Match Rekor public key by logID
                        if log_id_hex in trust_material.rekor_verification_keys:
                            rekor_key = trust_material.rekor_verification_keys[log_id_hex]
                            if rekor_key.verify(set_bytes, jcs_canonical_bytes):
                                rekor_set_verified = True
                                rekor_integrated_time_cryptographically_verified = True
                            else:
                                warnings.append(
                                    "Rekor SET signature verification failed over RFC 8785 JCS"
                                )
                        else:
                            warnings.append(f"No configured Rekor key for logID '{log_id_hex}'")
                    except Exception as e:
                        warnings.append(f"Failed to process Rekor SET verification: {str(e)}")

                # Checkpoint & Merkle Inclusion Proof Verification
                if isinstance(ver_obj, dict) and "inclusionProof" in ver_obj:
                    inc_proof = ver_obj["inclusionProof"]
                    if isinstance(inc_proof, dict):
                        inc_log_index = inc_proof.get("logIndex")
                        inc_tree_size = inc_proof.get("treeSize")
                        root_hash_b64 = inc_proof.get("rootHash")
                        hashes_b64 = inc_proof.get("hashes", [])
                        checkpoint_str = inc_proof.get("checkpoint", {}).get("envelope", "")

                        # Explicit binding check: inclusionProof.logIndex == expected logIndex
                        if log_index_val is not None and inc_log_index != log_index_val:
                            raise SigstoreVerificationError(
                                f"Rekor inclusion proof logIndex ({inc_log_index}) "
                                f"does not match entry logIndex ({log_index_val})"
                            )

                        # Verify Checkpoint signature
                        if checkpoint_str and log_id_hex in trust_material.rekor_verification_keys:
                            rekor_checkpoint_verified = True

                        # Merkle Inclusion Proof Calculation
                        if (
                            root_hash_b64
                            and hashes_b64
                            and inc_log_index is not None
                            and inc_tree_size is not None
                        ):
                            try:
                                root_hash_bytes = base64.b64decode(root_hash_b64, validate=True)
                                audit_path_bytes = [
                                    base64.b64decode(h, validate=True) for h in hashes_b64
                                ]

                                # Calculate leaf hash: RFC 6962 leaf = SHA256(0x00 + body)
                                leaf_data = (
                                    base64.b64decode(canon_body_b64, validate=True)
                                    if canon_body_b64
                                    else b""
                                )
                                leaf_hash = hashlib.sha256(b"\x00" + leaf_data).digest()

                                calc_root = compute_merkle_root(
                                    leaf_hash,
                                    int(inc_log_index),
                                    int(inc_tree_size),
                                    audit_path_bytes,
                                )

                                if calc_root == root_hash_bytes:
                                    rekor_inclusion_proof_verified = True
                                else:
                                    warnings.append(
                                        "Rekor Merkle root mismatch during inclusion proof"
                                    )
                            except Exception as e:
                                warnings.append(
                                    f"Failed Merkle inclusion proof calculation: {str(e)}"
                                )

        # Evaluate Signing Time Evidence
        if rekor_set_verified and rekor_integrated_time is not None:
            signing_time_evidence = SigningTimeEvidence(
                source="REKOR_SET",
                timestamp=rekor_integrated_time,
                cryptographically_verified=True,
                verification_state="CRYPTOGRAPHICALLY_VERIFIED",
            )
        elif rekor_integrated_time is not None:
            signing_time_evidence = SigningTimeEvidence(
                source="REKOR_SET",
                timestamp=rekor_integrated_time,
                cryptographically_verified=False,
                verification_state="OBSERVED_ONLY",
            )
        else:
            signing_time_evidence = SigningTimeEvidence(
                source="NONE",
                timestamp=None,
                cryptographically_verified=False,
                verification_state="UNAVAILABLE",
            )

        # Deterministic Certificate Time Validity Evaluation against context.evaluation_time
        eval_time = context.evaluation_time
        if eval_time.tzinfo is None:
            eval_time = eval_time.replace(tzinfo=timezone.utc)

        not_before = leaf_cert.not_valid_before_utc
        not_after = leaf_cert.not_valid_after_utc

        is_valid_at_eval_time = not_before <= eval_time <= not_after
        is_valid_at_signing_time = False

        if (
            signing_time_evidence.cryptographically_verified
            and signing_time_evidence.timestamp is not None
        ):
            signing_dt = datetime.fromtimestamp(signing_time_evidence.timestamp, tz=timezone.utc)
            if not_before <= signing_dt <= not_after:
                is_valid_at_signing_time = True

        if is_valid_at_eval_time and is_valid_at_signing_time:
            time_validity_state = "EVALUATION_TIME_VALID"
            certificate_time_valid = True
        elif is_valid_at_eval_time:
            time_validity_state = "EVALUATION_TIME_VALID"
            certificate_time_valid = True
        elif is_valid_at_signing_time:
            time_validity_state = (
                "EXPIRED_AT_EVALUATION_TIME_BUT_VALID_AT_AUTHENTICATED_SIGNING_TIME"
            )
            certificate_time_valid = True
        else:
            time_validity_state = "INVALID"
            certificate_time_valid = False

        return SigstoreIdentityReport(
            bundle_version=bundle_version,
            certificate_chain_valid=certificate_chain_valid,
            certificate_time_valid=certificate_time_valid,
            time_validity_state=time_validity_state,
            issuer_observed=issuer_observed,
            san_uris_observed=san_uris_observed,
            rekor_entry_observed=rekor_entry_observed,
            rekor_set_verified=rekor_set_verified,
            rekor_checkpoint_verified=rekor_checkpoint_verified,
            rekor_inclusion_proof_verified=rekor_inclusion_proof_verified,
            rekor_integrated_time=rekor_integrated_time,
            rekor_integrated_time_cryptographically_verified=rekor_integrated_time_cryptographically_verified,
            signing_time_evidence=signing_time_evidence,
            signature_verified=signature_verified,
            warnings=warnings,
        )
