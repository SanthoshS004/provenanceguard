"""
Verification Trust Material, Key Wrappers, and Verification Context.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import Certificate
from pydantic import BaseModel, ConfigDict, Field


class VerificationAlgorithm(str, Enum):
    """Explicit Cryptographic Verification Algorithm Profiles."""

    ED25519 = "ED25519"
    ECDSA_P256_SHA256 = "ECDSA_P256_SHA256"
    RSA_PSS_SHA256 = "RSA_PSS_SHA256"
    RSA_PKCS1_SHA256 = "RSA_PKCS1_SHA256"


class VerificationKey(BaseModel):
    """Wrapper around a public verification key and its algorithm profile."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    key_id: Optional[str] = None
    algorithm: VerificationAlgorithm
    public_key: Any  # cryptography public key instance

    def verify(self, signature: bytes, data: bytes) -> bool:
        """
        Verify signature over data using exact algorithm profile.
        Returns True if signature is cryptographically valid, False if invalid signature.
        Raises ValueError on malformed parameters or algorithm mismatch.
        """
        if not signature or not isinstance(signature, bytes):
            return False
        if not isinstance(data, bytes):
            return False

        try:
            if self.algorithm == VerificationAlgorithm.ED25519:
                if not isinstance(self.public_key, ed25519.Ed25519PublicKey):
                    return False
                self.public_key.verify(signature, data)
                return True

            elif self.algorithm == VerificationAlgorithm.ECDSA_P256_SHA256:
                if not isinstance(self.public_key, ec.EllipticCurvePublicKey):
                    return False
                if not isinstance(self.public_key.curve, ec.SECP256R1):
                    return False
                self.public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
                return True

            elif self.algorithm == VerificationAlgorithm.RSA_PSS_SHA256:
                if not isinstance(self.public_key, rsa.RSAPublicKey):
                    return False
                self.public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH,
                    ),
                    hashes.SHA256(),
                )
                return True

            elif self.algorithm == VerificationAlgorithm.RSA_PKCS1_SHA256:
                if not isinstance(self.public_key, rsa.RSAPublicKey):
                    return False
                self.public_key.verify(
                    signature,
                    data,
                    padding.PKCS1v15(),
                    hashes.SHA256(),
                )
                return True

            else:
                return False

        except InvalidSignature:
            return False
        except (ValueError, TypeError):
            return False


class VerificationContext(BaseModel):
    """Injected execution context for deterministic verification."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    evaluation_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationTrustMaterial(BaseModel):
    """Injectable trust material configuration."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dsse_public_keys: Dict[str, VerificationKey] = Field(default_factory=dict)
    fulcio_root_certificates: List[Certificate] = Field(default_factory=list)
    rekor_verification_keys: Dict[str, VerificationKey] = Field(default_factory=dict)
    timestamp_verification_roots: List[Certificate] = Field(default_factory=list)
