"""
Domain Models, Enums, and Value Objects for Verification Subsystem
"""

from enum import Enum
from typing import Any, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict


class FunctionInventoryCompleteness(str, Enum):
    """Represents the completeness state of function inventory analysis."""

    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


class SectionMatchKey(BaseModel):
    """Primary identity key for matching binary sections."""

    model_config = ConfigDict(frozen=True)

    name: str
    section_type: int

    def key_tuple(self) -> Tuple[str, int]:
        return (self.name, self.section_type)


class FunctionMatchKey(BaseModel):
    """Identity key for matching function symbols."""

    model_config = ConfigDict(frozen=True)

    name: str
    section_name: str
    binding: str

    def key_tuple(self) -> Tuple[str, str, str]:
        return (self.name, self.section_name, self.binding)


class FunctionMetadata(BaseModel):
    """Symbolic metadata for a single function."""

    name: str
    section_index: int
    section_name: str
    symbol_type: str
    binding: str
    offset: int
    size: int
    address: int


class FunctionCodeDigest(BaseModel):
    """Digest value object representing raw bytecode SHA-256 for a function."""

    function_name: str
    raw_bytes_sha256: Optional[str] = None
    size_bytes: int
    is_zero_size: bool = False
    is_valid_range: bool = True
    warning: Optional[str] = None


class StructuralDelta(BaseModel):
    """Represents structural binary section modifications."""

    # delta_type options: SECTION_ADDED, SECTION_REMOVED, SECTION_RENAMED,
    # SECTION_CONTENT_CHANGED, SECTION_FLAGS_CHANGED, SECTION_SIZE_CHANGED,
    # SECTION_REORDERED
    delta_type: str
    section_name: str
    details: str
    old_value: Optional[Any] = None
    new_value: Optional[Any] = None


class FunctionDelta(BaseModel):
    """Represents function code or symbol modifications."""

    # delta_type options: ADDED_FUNCTION, REMOVED_FUNCTION,
    # MODIFIED_FUNCTION_CODE, FUNCTION_SIZE_CHANGED
    delta_type: str
    function_name: str
    details: str
    old_digest: Optional[str] = None
    new_digest: Optional[str] = None


class DependencyDelta(BaseModel):
    """Represents dynamic library dependency modifications."""

    # delta_type options: ADDED_DEPENDENCY, REMOVED_DEPENDENCY
    delta_type: str
    library_name: str
    details: str


class SecurityObservationDelta(BaseModel):
    """Represents changes in objective security observations (W+X permissions)."""

    # observation_type options: WX_SECTION_INTRODUCED, WX_SECTION_REMOVED,
    # WX_LOAD_SEGMENT_INTRODUCED, WX_LOAD_SEGMENT_REMOVED,
    # SECTION_PERMISSION_CHANGED, SEGMENT_PERMISSION_CHANGED
    observation_type: str
    target_name: str
    details: str


class ComparisonResult(BaseModel):
    """
    100% Deterministic Evidence Payload for Artifact Comparison.
    Contains ONLY objective evidence, zero policy verdicts (PASS/BLOCK), zero risk scores.
    """

    reference_artifact_digest: str
    target_artifact_digest: str
    digest_matches: bool
    reference_completeness: FunctionInventoryCompleteness
    target_completeness: FunctionInventoryCompleteness
    is_partial_comparison: bool
    structural_deltas: List[StructuralDelta] = []
    function_deltas: List[FunctionDelta] = []
    dependency_deltas: List[DependencyDelta] = []
    security_observation_deltas: List[SecurityObservationDelta] = []
    warnings: List[str] = []

    def sort_deltas(self) -> "ComparisonResult":
        """
        Sorts all delta collections deterministically to guarantee stable JSON output across runs.
        """
        self.structural_deltas.sort(
            key=lambda d: (d.delta_type, d.section_name, str(d.old_value), str(d.new_value))
        )
        self.function_deltas.sort(
            key=lambda f: (f.delta_type, f.function_name, str(f.old_digest), str(f.new_digest))
        )
        self.dependency_deltas.sort(key=lambda dep: (dep.delta_type, dep.library_name))
        self.security_observation_deltas.sort(key=lambda s: (s.observation_type, s.target_name))
        self.warnings.sort()
        return self


class ComparisonExecutionMetadata(BaseModel):
    """Non-deterministic execution audit metadata kept separate from ComparisonResult."""

    comparison_run_id: str
    timestamp_iso: str
    verifier_version: str
    duration_ms: float
