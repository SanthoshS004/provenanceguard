"""
Generic Bounded DSSE Envelope & Exact-Byte PAE Verifier.
"""

import base64
import hashlib
import json
from typing import Any, Dict, List, Union

from provenanceguard.core.verification.exceptions import DSSEVerificationError
from provenanceguard.core.verification.provenance_models import DSSEVerificationReport
from provenanceguard.core.verification.trust import VerificationTrustMaterial

# Resource limit constants
MAX_DSSE_ENVELOPE_SIZE = 2 * 1024 * 1024  # 2 MB
MAX_DSSE_PAYLOAD_SIZE = 1 * 1024 * 1024  # 1 MB
MAX_DSSE_PAYLOAD_TYPE_SIZE = 256  # 256 B
MAX_DSSE_SIGNATURE_COUNT = 32
MAX_DSSE_SIGNATURE_SIZE = 4096  # 4 KB


def compute_dsse_pae(payload_type: str, payload_bytes: bytes) -> bytes:
    """
    Compute Pre-Authentication Encoding (PAE) according to DSSE v1 specification.
    PAE(type, payload) = "DSSEv1 " + len(type) + " " + type + " " + len(payload) + " " + payload
    Uses exact ASCII decimal length representations and exact raw payload bytes.
    """
    type_bytes = payload_type.encode("utf-8")
    pae = (
        b"DSSEv1 "
        + str(len(type_bytes)).encode("ascii")
        + b" "
        + type_bytes
        + b" "
        + str(len(payload_bytes)).encode("ascii")
        + b" "
        + payload_bytes
    )
    return pae


class DSSEVerifier:
    """Generic protocol verifier for DSSE (Dead Simple Signing Envelope) v1."""

    def verify_envelope(
        self,
        envelope_data: Union[Dict[str, Any], str, bytes],
        trust_material: VerificationTrustMaterial,
    ) -> DSSEVerificationReport:
        """
        Verify DSSE envelope using strict resource limits, exact-byte PAE,
        and deterministic key-ID selection.
        """
        warnings: List[str] = []

        # Envelope size boundary check
        if isinstance(envelope_data, (str, bytes)):
            raw_bytes = (
                envelope_data.encode("utf-8") if isinstance(envelope_data, str) else envelope_data
            )
            if len(raw_bytes) > MAX_DSSE_ENVELOPE_SIZE:
                raise DSSEVerificationError(
                    f"DSSE envelope size ({len(raw_bytes)} bytes) "
                    f"exceeds limit ({MAX_DSSE_ENVELOPE_SIZE} bytes)"
                )
            try:
                envelope = json.loads(raw_bytes)
            except Exception as e:
                raise DSSEVerificationError(f"Failed to parse DSSE envelope JSON: {str(e)}") from e
        elif isinstance(envelope_data, dict):
            raw_bytes = json.dumps(envelope_data).encode("utf-8")
            if len(raw_bytes) > MAX_DSSE_ENVELOPE_SIZE:
                raise DSSEVerificationError(
                    f"DSSE envelope size ({len(raw_bytes)} bytes) "
                    f"exceeds limit ({MAX_DSSE_ENVELOPE_SIZE} bytes)"
                )
            envelope = envelope_data
        else:
            raise DSSEVerificationError("Invalid DSSE envelope data type")

        if not isinstance(envelope, dict):
            raise DSSEVerificationError("DSSE envelope must be a JSON object")

        payload_b64 = envelope.get("payload")
        payload_type = envelope.get("payloadType")
        signatures = envelope.get("signatures")

        if not isinstance(payload_b64, str):
            raise DSSEVerificationError("DSSE envelope missing string 'payload'")
        if not isinstance(payload_type, str):
            raise DSSEVerificationError("DSSE envelope missing string 'payloadType'")
        if not isinstance(signatures, list):
            raise DSSEVerificationError("DSSE envelope missing array 'signatures'")

        # Resource limit checks
        if len(payload_type.encode("utf-8")) > MAX_DSSE_PAYLOAD_TYPE_SIZE:
            raise DSSEVerificationError(
                f"DSSE payloadType length exceeds limit ({MAX_DSSE_PAYLOAD_TYPE_SIZE} bytes)"
            )

        if len(signatures) == 0:
            raise DSSEVerificationError("DSSE envelope contains zero signatures")
        if len(signatures) > MAX_DSSE_SIGNATURE_COUNT:
            raise DSSEVerificationError(
                f"DSSE signature count ({len(signatures)}) "
                f"exceeds limit ({MAX_DSSE_SIGNATURE_COUNT})"
            )

        # Base64 decode payload
        try:
            decoded_payload = base64.b64decode(payload_b64, validate=True)
        except Exception as e:
            raise DSSEVerificationError(f"Failed to base64-decode DSSE payload: {str(e)}") from e

        if len(decoded_payload) > MAX_DSSE_PAYLOAD_SIZE:
            raise DSSEVerificationError(
                f"DSSE decoded payload size ({len(decoded_payload)} bytes) "
                f"exceeds limit ({MAX_DSSE_PAYLOAD_SIZE} bytes)"
            )

        payload_sha256 = hashlib.sha256(decoded_payload).hexdigest()
        pae_bytes = compute_dsse_pae(payload_type, decoded_payload)

        key_ids_verified: List[str] = []
        signatures_verified_count = 0

        for idx, sig_entry in enumerate(signatures):
            if not isinstance(sig_entry, dict):
                raise DSSEVerificationError(
                    f"DSSE signature entry at index {idx} must be a JSON object"
                )

            sig_b64 = sig_entry.get("sig")
            key_id = sig_entry.get("keyid")

            if not isinstance(sig_b64, str):
                raise DSSEVerificationError(
                    f"DSSE signature entry at index {idx} missing string 'sig'"
                )

            try:
                sig_bytes = base64.b64decode(sig_b64, validate=True)
            except Exception as e:
                raise DSSEVerificationError(
                    f"Failed to base64-decode DSSE signature at index {idx}: {str(e)}"
                ) from e

            if len(sig_bytes) > MAX_DSSE_SIGNATURE_SIZE:
                raise DSSEVerificationError(
                    f"DSSE signature size at index {idx} "
                    f"exceeds limit ({MAX_DSSE_SIGNATURE_SIZE} bytes)"
                )

            # Deterministic Key-ID Selection
            if key_id is not None and key_id != "":
                if key_id not in trust_material.dsse_public_keys:
                    raise DSSEVerificationError(f"Unknown DSSE signature keyid '{key_id}'")

                key_wrapper = trust_material.dsse_public_keys[key_id]
                if not key_wrapper.verify(sig_bytes, pae_bytes):
                    raise DSSEVerificationError(f"Invalid DSSE signature for keyid '{key_id}'")

                key_ids_verified.append(key_id)
                signatures_verified_count += 1
            else:
                # Key ID is absent -> attempt verification against eligible candidate keys
                if not trust_material.dsse_public_keys:
                    raise DSSEVerificationError(
                        "No configured public keys available for signature with absent keyid"
                    )

                successful_candidates: List[tuple[str, Any]] = []
                for cand_id, cand_key in trust_material.dsse_public_keys.items():
                    if cand_key.verify(sig_bytes, pae_bytes):
                        successful_candidates.append((cand_id, cand_key))

                if len(successful_candidates) == 0:
                    raise DSSEVerificationError(
                        "Zero candidate keys verified DSSE signature with absent keyid"
                    )
                elif len(successful_candidates) > 1:
                    raise DSSEVerificationError(
                        f"Ambiguous DSSE key-ID: {len(successful_candidates)} "
                        "candidate keys verified signature with absent keyid"
                    )
                else:
                    selected_id, _ = successful_candidates[0]
                    key_ids_verified.append(selected_id)
                    signatures_verified_count += 1
                    warnings.append(
                        "DSSE signature keyid was absent; verified against candidate key "
                        f"'{selected_id}'"
                    )

        return DSSEVerificationReport(
            payload_type=payload_type,
            payload_sha256=payload_sha256,
            decoded_payload_size=len(decoded_payload),
            signatures_observed=len(signatures),
            signatures_verified=signatures_verified_count,
            key_ids_verified=key_ids_verified,
            signature_verified=(
                signatures_verified_count > 0 and signatures_verified_count == len(signatures)
            ),
            warnings=warnings,
        )
