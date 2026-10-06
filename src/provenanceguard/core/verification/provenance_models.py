"""
Strongly Typed Evidence Domain Models & Recursive JsonValue Abstraction.
"""

from typing import Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, JsonValue

# Recursive JSON Value Abstraction for open-ended parameters & unknown extension preservation
JsonPrimitive = Union[None, bool, int, float, str]


class SubjectEvidence(BaseModel):
    """Evidence model for an individual subject in an in-toto statement."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    name: Optional[str] = None
    digest_algorithm: str
    digest: str
    extension_evidence: Dict[str, JsonValue] = Field(default_factory=dict)


class SubjectCorrelationDetails(BaseModel):
    """Subject correlation evidence details."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target_artifact_sha256: str
    matching_mode: (
        str  # EXACT_ONE_MATCH, MULTIPLE_SUBJECTS_MATCH, ZERO_SUBJECT_MATCH, ALGORITHM_UNSUPPORTED
    )
    matching_subject_count: int
    matching_subject_indices: List[int] = Field(default_factory=list)
    matched_subjects: List[SubjectEvidence] = Field(default_factory=list)
    subject_digest_match: bool  # True ONLY when matching_subject_count == 1
    all_subjects_observed: List[SubjectEvidence] = Field(default_factory=list)


class BuildDefinitionEvidence(BaseModel):
    """SLSA buildDefinition evidence model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    build_type: str
    external_parameters: Dict[str, JsonValue] = Field(default_factory=dict)
    internal_parameters: Dict[str, JsonValue] = Field(default_factory=dict)
    resolved_dependencies: List[Dict[str, JsonValue]] = Field(default_factory=list)
    extension_evidence: Dict[str, JsonValue] = Field(default_factory=dict)


class RunDetailsEvidence(BaseModel):
    """SLSA runDetails evidence model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    builder_id: Optional[str] = None
    builder_metadata: Dict[str, JsonValue] = Field(default_factory=dict)
    byproducts: List[Dict[str, JsonValue]] = Field(default_factory=list)
    extension_evidence: Dict[str, JsonValue] = Field(default_factory=dict)


class DSSEVerificationReport(BaseModel):
    """Objective evidence report for DSSE envelope verification."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    payload_type: str
    payload_sha256: str
    decoded_payload_size: int
    signatures_observed: int
    signatures_verified: int
    key_ids_verified: List[str] = Field(default_factory=list)
    signature_verified: bool
    warnings: List[str] = Field(default_factory=list)


class SigningTimeEvidence(BaseModel):
    """Cryptographic signing-time evidence model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source: str  # REKOR_SET, RFC3161, NONE
    timestamp: Optional[int] = None
    cryptographically_verified: bool = False
    verification_state: str  # CRYPTOGRAPHICALLY_VERIFIED, OBSERVED_ONLY, UNAVAILABLE


class SLSAProvenanceReport(BaseModel):
    """Objective evidence report for in-toto Statement v1 & SLSA v1.2 statement validation."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    statement_version: str = "https://in-toto.io/Statement/v1"
    predicate_type: str = "https://slsa.dev/provenance/v1"
    build_definition: BuildDefinitionEvidence
    run_details: RunDetailsEvidence
    subject_correlation: SubjectCorrelationDetails
    extension_evidence: Dict[str, JsonValue] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)


class SigstoreIdentityReport(BaseModel):
    """Objective evidence report for Sigstore bundle, Fulcio identity, and Rekor tlog."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    bundle_version: str
    certificate_chain_valid: bool
    certificate_time_valid: bool
    time_validity_state: str  # EVALUATION_TIME_VALID, VALID_AT_AUTHENTICATED_SIGNING_TIME, etc.
    issuer_observed: Optional[str] = None
    san_uris_observed: List[str] = Field(default_factory=list)
    rekor_entry_observed: bool = False
    rekor_set_verified: bool = False
    rekor_checkpoint_verified: bool = False
    rekor_inclusion_proof_verified: bool = False
    rekor_integrated_time: Optional[int] = None
    rekor_integrated_time_cryptographically_verified: bool = False
    signing_time_evidence: SigningTimeEvidence = Field(
        default_factory=lambda: SigningTimeEvidence(source="NONE", verification_state="UNAVAILABLE")
    )
    signature_verified: bool = False
    warnings: List[str] = Field(default_factory=list)


class CombinedAttestationVerificationReport(BaseModel):
    """Aggregated evidence payload combining DSSE, SLSA, Subject, Identity evidence."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    dsse_report: Optional[DSSEVerificationReport] = None
    slsa_report: Optional[SLSAProvenanceReport] = None
    sigstore_report: Optional[SigstoreIdentityReport] = None
    warnings: List[str] = Field(default_factory=list)
