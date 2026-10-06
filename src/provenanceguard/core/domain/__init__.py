"""
Core Domain Package for ProvenanceGuard
Exports entities, value objects, adapters, stubs, enums, and exceptions.
"""

from provenanceguard.core.domain.adapters import (
    DSSEEnvelope,
    DSSESignature,
    InTotoStatement,
    SLSABuildDefinition,
    SLSAProvenanceV12,
    SLSARunDetails,
)
from provenanceguard.core.domain.entities import (
    Artifact,
    Build,
    BuilderProfile,
    Organization,
    Project,
    Provenance,
    Repository,
    VerificationDecision,
    VerificationResult,
)
from provenanceguard.core.domain.enums import (
    AttestationType,
    Decision,
    DigestAlgorithm,
    ExecutionStatus,
    FindingCategory,
    MediaType,
    ScmProvider,
    Severity,
)
from provenanceguard.core.domain.exceptions import (
    DomainError,
    DomainValidationError,
    IngestionRejectedError,
)
from provenanceguard.core.domain.stubs import (
    Policy,
    PolicyRule,
    Risk,
    RiskRule,
)
from provenanceguard.core.domain.value_objects import (
    ArtifactDigest,
    Attestation,
    BuildMaterial,
    EnvironmentVariable,
    Finding,
)

__all__ = [
    # Entities
    "Organization",
    "Project",
    "Repository",
    "BuilderProfile",
    "Artifact",
    "Build",
    "Provenance",
    "VerificationResult",
    "VerificationDecision",
    # Value Objects
    "ArtifactDigest",
    "BuildMaterial",
    "EnvironmentVariable",
    "Attestation",
    "Finding",
    # External Adapters
    "SLSABuildDefinition",
    "SLSARunDetails",
    "SLSAProvenanceV12",
    "InTotoStatement",
    "DSSESignature",
    "DSSEEnvelope",
    # Declarative Stubs
    "RiskRule",
    "Risk",
    "PolicyRule",
    "Policy",
    # Enums
    "MediaType",
    "DigestAlgorithm",
    "ScmProvider",
    "ExecutionStatus",
    "Severity",
    "FindingCategory",
    "Decision",
    "AttestationType",
    # Exceptions
    "DomainError",
    "DomainValidationError",
    "IngestionRejectedError",
]
