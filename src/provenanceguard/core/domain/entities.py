"""
Identity-Bearing Domain Entities for ProvenanceGuard
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from provenanceguard.core.domain.enums import (
    Decision,
    ExecutionStatus,
    MediaType,
    ScmProvider,
)
from provenanceguard.core.domain.exceptions import DomainValidationError
from provenanceguard.core.domain.value_objects import (
    ArtifactDigest,
    BuildMaterial,
    EnvironmentVariable,
    Finding,
)


class Organization(BaseModel):
    """Organization entity boundary."""

    id: str = Field(..., max_length=256)
    name: str = Field(..., max_length=256)
    slug: str = Field(..., max_length=100)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Project(BaseModel):
    """Project entity under Organization."""

    id: str = Field(..., max_length=256)
    organization_id: str = Field(..., max_length=256)
    name: str = Field(..., max_length=256)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Repository(BaseModel):
    """SCM Repository reference entity."""

    id: str = Field(..., max_length=256)
    project_id: str = Field(..., max_length=256)
    provider: ScmProvider
    url: str = Field(..., max_length=1024)
    default_branch: str = Field(default="main", max_length=256)


class BuilderProfile(BaseModel):
    """Reference / Production Builder profile entity."""

    id: str = Field(..., max_length=256)
    name: str = Field(..., max_length=256)
    builder_type: str = Field(..., max_length=100)
    pinned_image: Optional[str] = Field(default=None, max_length=1024)
    is_trusted: bool = False


class Artifact(BaseModel):
    """
    Core software artifact entity abstraction.
    """

    id: str = Field(..., max_length=256)
    project_id: str = Field(..., max_length=256)
    name: str = Field(..., max_length=256)
    version: str = Field(..., max_length=100)
    media_type: MediaType
    digests: List[ArtifactDigest] = Field(default_factory=list)
    size_bytes: int = Field(..., ge=0, le=5 * 1024 * 1024 * 1024)  # Max 5GB limit
    storage_reference: Optional[str] = Field(default=None, max_length=1024)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not v.strip():
            raise DomainValidationError("Artifact name cannot be empty", field_name="name")
        return v.strip()


class Build(BaseModel):
    """
    Build execution metadata entity.
    """

    id: str = Field(..., max_length=256)
    project_id: str = Field(..., max_length=256)
    builder_profile_id: str = Field(..., max_length=256)
    source_revision: str = Field(..., max_length=256)
    invocation_args: List[str] = Field(default_factory=list)
    environment: List[EnvironmentVariable] = Field(default_factory=list)
    materials: List[BuildMaterial] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Provenance(BaseModel):
    """
    Normalized internal build provenance entity.
    Independent of specific external SLSA/in-toto specifications.
    """

    id: str = Field(..., max_length=256)
    artifact_id: str = Field(..., max_length=256)
    build_id: str = Field(..., max_length=256)
    source_commit: str = Field(..., max_length=256)
    builder_identity: str = Field(..., max_length=512)
    build_type: str = Field(..., max_length=256)
    invocation: Dict[str, Any] = Field(default_factory=dict)
    materials: List[BuildMaterial] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationResult(BaseModel):
    """
    Verification execution output & evidence.
    CRITICAL INVARIANT: VerificationResult represents execution output/evidence.
    It MUST NOT contain policy decisions (PASS/BLOCK) or risk scores!
    """

    id: str = Field(..., max_length=256)
    verification_run_id: str = Field(..., max_length=256)
    artifact_id: str = Field(..., max_length=256)
    reference_artifact_id: Optional[str] = Field(default=None, max_length=256)
    status: ExecutionStatus
    findings: List[Finding] = Field(default_factory=list)
    evidence_references: List[str] = Field(default_factory=list)
    verifier_version: str = Field(default="1.0.0", max_length=50)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VerificationDecision(BaseModel):
    """
    Policy Gate Decision outcome owned exclusively by the Policy Engine.
    """

    id: str = Field(..., max_length=256)
    verification_run_id: str = Field(..., max_length=256)
    policy_id: str = Field(..., max_length=256)
    decision: Decision
    rationale: str = Field(..., max_length=4096)
    finding_references: List[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
