"""
Value Objects for ProvenanceGuard Domain Layer
Immutable, identity-less data structures.
"""

import re
from typing import Any, ClassVar, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from provenanceguard.core.domain.enums import (
    AttestationType,
    DigestAlgorithm,
    FindingCategory,
    Severity,
)
from provenanceguard.core.domain.exceptions import DomainValidationError


class ArtifactDigest(BaseModel):
    """
    Cryptographic digest value object. Immutable.
    """

    model_config = ConfigDict(frozen=True)

    algorithm: DigestAlgorithm
    value: str

    @field_validator("value")
    @classmethod
    def validate_digest_hex(cls, v: str, info) -> str:
        v_clean = v.strip().lower()
        if not re.match(r"^[a-f0-9]+$", v_clean):
            raise DomainValidationError(
                "Digest value must be hexadecimal string", field_name="value"
            )

        algo = info.data.get("algorithm")
        if algo == DigestAlgorithm.SHA256 and len(v_clean) != 64:
            raise DomainValidationError(
                f"SHA-256 digest hex length must be 64 characters, got {len(v_clean)}",
                field_name="value",
            )
        if algo == DigestAlgorithm.SHA512 and len(v_clean) != 128:
            raise DomainValidationError(
                f"SHA-512 digest hex length must be 128 characters, got {len(v_clean)}",
                field_name="value",
            )
        return v_clean


class BuildMaterial(BaseModel):
    """
    Bounded material/dependency reference used in build. Immutable.
    """

    model_config = ConfigDict(frozen=True)

    uri: str = Field(..., max_length=2048)
    digest: Optional[ArtifactDigest] = None
    material_type: str = Field(default="dependency", max_length=100)

    @field_validator("uri")
    @classmethod
    def validate_uri(cls, v: str) -> str:
        if not v.strip():
            raise DomainValidationError("BuildMaterial URI cannot be empty", field_name="uri")
        return v.strip()


class EnvironmentVariable(BaseModel):
    """
    Bounded representation of build environment variables.
    Enforces security boundary: Prohibits raw secret keys/credentials from being submitted
    as ordinary domain metadata. Rejects prohibited credential keys rather than mutating them.
    """

    model_config = ConfigDict(frozen=True)

    key: str = Field(..., max_length=256)
    value: str = Field(..., max_length=4096)
    is_sensitive: bool = False

    PROHIBITED_SECRET_PATTERNS: ClassVar[tuple[str, ...]] = (
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "PRIVATE_KEY",
        "SECRET_KEY",
        "PASSWORD",
        "PASSPHRASE",
        "API_TOKEN",
        "AUTH_TOKEN",
        "ACCESS_TOKEN",
    )

    @field_validator("key")
    @classmethod
    def validate_key(cls, v: str) -> str:
        v_upper = v.strip().upper()
        if not v_upper:
            raise DomainValidationError(
                "Environment variable key cannot be empty", field_name="key"
            )

        # Check against prohibited secret keys
        for pattern in cls.PROHIBITED_SECRET_PATTERNS:
            if pattern in v_upper:
                raise DomainValidationError(
                    f"Prohibited secret environment variable key '{v}' "
                    "cannot be stored as ordinary domain metadata",
                    field_name="key",
                )
        return v.strip()


class Attestation(BaseModel):
    """
    General attestation value object metadata. Immutable.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., max_length=256)
    attestation_type: AttestationType
    predicate_type: str = Field(..., max_length=256)
    subject_digest: ArtifactDigest
    issuer: Optional[str] = Field(default=None, max_length=512)


class Finding(BaseModel):
    """
    Observed verification discrepancy or evidence item. Immutable.
    """

    model_config = ConfigDict(frozen=True)

    id: str = Field(..., max_length=256)
    severity: Severity
    category: FindingCategory
    subject: str = Field(..., max_length=512)
    explanation: str = Field(..., max_length=4096)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    remediation: Optional[str] = Field(default=None, max_length=2048)
