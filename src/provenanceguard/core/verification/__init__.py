"""
Verification & Attestation Subsystem Exports.
"""

from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.comparison import ArtifactComparator
from provenanceguard.core.verification.dsse import DSSEVerifier, compute_dsse_pae
from provenanceguard.core.verification.exceptions import (
    AuthoritativeDigestMismatchError,
    ComparisonError,
    DSSEVerificationError,
    ELFCompatibilityError,
    IncompatibleArtifactTypeError,
    ProvenanceValidationError,
    SigstoreVerificationError,
    SubjectDigestMismatchFinding,
    VerificationError,
)
from provenanceguard.core.verification.fingerprinting import FunctionFingerprinter
from provenanceguard.core.verification.matching import ArtifactMatcher
from provenanceguard.core.verification.models import (
    ComparisonExecutionMetadata,
    ComparisonResult,
    DependencyDelta,
    FunctionCodeDigest,
    FunctionDelta,
    FunctionInventoryCompleteness,
    FunctionMatchKey,
    FunctionMetadata,
    SectionMatchKey,
    SecurityObservationDelta,
    StructuralDelta,
)
from provenanceguard.core.verification.provenance import SLSAProvenanceValidator
from provenanceguard.core.verification.provenance_models import (
    BuildDefinitionEvidence,
    CombinedAttestationVerificationReport,
    DSSEVerificationReport,
    JsonValue,
    RunDetailsEvidence,
    SigningTimeEvidence,
    SigstoreIdentityReport,
    SLSAProvenanceReport,
    SubjectCorrelationDetails,
    SubjectEvidence,
)
from provenanceguard.core.verification.sigstore import SigstoreVerifier, compute_merkle_root
from provenanceguard.core.verification.trust import (
    VerificationAlgorithm,
    VerificationContext,
    VerificationKey,
    VerificationTrustMaterial,
)

__all__ = [
    "BoundedArtifactReader",
    "ArtifactComparator",
    "ArtifactMatcher",
    "FunctionFingerprinter",
    "ComparisonError",
    "AuthoritativeDigestMismatchError",
    "ELFCompatibilityError",
    "IncompatibleArtifactTypeError",
    "VerificationError",
    "DSSEVerificationError",
    "ProvenanceValidationError",
    "SigstoreVerificationError",
    "SubjectDigestMismatchFinding",
    "FunctionInventoryCompleteness",
    "SectionMatchKey",
    "FunctionMatchKey",
    "FunctionMetadata",
    "FunctionCodeDigest",
    "StructuralDelta",
    "FunctionDelta",
    "DependencyDelta",
    "SecurityObservationDelta",
    "ComparisonResult",
    "ComparisonExecutionMetadata",
    "DSSEVerifier",
    "compute_dsse_pae",
    "SLSAProvenanceValidator",
    "SigstoreVerifier",
    "compute_merkle_root",
    "VerificationAlgorithm",
    "VerificationKey",
    "VerificationContext",
    "VerificationTrustMaterial",
    "JsonValue",
    "SubjectEvidence",
    "SubjectCorrelationDetails",
    "BuildDefinitionEvidence",
    "RunDetailsEvidence",
    "DSSEVerificationReport",
    "SigningTimeEvidence",
    "SLSAProvenanceReport",
    "SigstoreIdentityReport",
    "CombinedAttestationVerificationReport",
]
