"""
Artifact Comparison Engine & Orchestrator
"""

from typing import List, Set

from provenanceguard.analyzers.elf.models import ELFAnalysisReport
from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.exceptions import (
    ELFCompatibilityError,
    IncompatibleArtifactTypeError,
)
from provenanceguard.core.verification.fingerprinting import FunctionFingerprinter
from provenanceguard.core.verification.matching import ArtifactMatcher
from provenanceguard.core.verification.models import (
    ComparisonResult,
    DependencyDelta,
    FunctionDelta,
    FunctionInventoryCompleteness,
    SecurityObservationDelta,
)

ELF_MEDIA_TYPES: Set[str] = {
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-object",
    "application/x-elf",
    "ELF",
}


class ArtifactComparator:
    """
    Deterministic static artifact comparison engine.
    Orchestrates compatibility checks, structural deltas, function byte fingerprinting,
    and granular observation deltas while guaranteeing zero policy verdicts or risk scores.
    """

    @staticmethod
    def compare_elf_artifacts(
        reference_report: ELFAnalysisReport,
        target_report: ELFAnalysisReport,
        reference_reader: BoundedArtifactReader,
        target_reader: BoundedArtifactReader,
        reference_digest: str,
        target_digest: str,
        reference_media_type: str = "application/x-elf",
        target_media_type: str = "application/x-elf",
    ) -> ComparisonResult:
        """
        Compares two ELF artifacts statically using their analysis reports and bounded readers.
        """
        # 1. Media Type Compatibility Validation (PG-4002)
        ref_is_elf = reference_media_type in ELF_MEDIA_TYPES
        target_is_elf = target_media_type in ELF_MEDIA_TYPES
        if not (ref_is_elf and target_is_elf):
            raise IncompatibleArtifactTypeError(
                reference_type=reference_media_type,
                target_type=target_media_type,
            )

        # 2. ELF Header Compatibility Validation (PG-4001)
        ref_h = reference_report.header
        target_h = target_report.header

        if ref_h.e_class != target_h.e_class:
            raise ELFCompatibilityError(
                f"ELF class mismatch: reference {ref_h.class_name} vs target {target_h.class_name}"
            )

        if ref_h.endianness != target_h.endianness:
            raise ELFCompatibilityError(
                f"ELF endianness mismatch: reference '{ref_h.endianness}' "
                f"vs target '{target_h.endianness}'"
            )

        if ref_h.e_machine != target_h.e_machine:
            raise ELFCompatibilityError(
                f"ELF raw machine ID (e_machine) mismatch: "
                f"reference {ref_h.e_machine} ({ref_h.architecture_name}) "
                f"vs target {target_h.e_machine} ({target_h.architecture_name})"
            )

        # 3. Whole-File Digest Equality
        digest_matches = reference_digest.lower() == target_digest.lower()

        # 4. Inventory Completeness Determination
        def determine_completeness(report: ELFAnalysisReport) -> FunctionInventoryCompleteness:
            if (
                not report.sections
                and not report.symbol_derived_functions
                and not report.all_symbols
            ):
                return FunctionInventoryCompleteness.UNAVAILABLE
            if report.is_stripped or report.is_truncated:
                return FunctionInventoryCompleteness.PARTIAL
            return FunctionInventoryCompleteness.COMPLETE

        ref_completeness = determine_completeness(reference_report)
        target_completeness = determine_completeness(target_report)
        is_partial_comparison = (
            ref_completeness != FunctionInventoryCompleteness.COMPLETE
            or target_completeness != FunctionInventoryCompleteness.COMPLETE
        )

        warnings: List[str] = []
        if is_partial_comparison:
            warnings.append(
                f"Comparison performed under PARTIAL function inventory completeness "
                f"(reference={ref_completeness.value}, target={target_completeness.value}). "
                f"Function removal deltas suppressed to prevent false negative findings."
            )

        # 5. Section Structural Deltas
        structural_deltas = ArtifactMatcher.compare_sections(
            ref_sections=reference_report.sections,
            target_sections=target_report.sections,
        )

        # 6. Function Matching and Byte Code Fingerprinting
        function_deltas: List[FunctionDelta] = []
        ref_func_map = ArtifactMatcher.build_function_map(
            reference_report.symbol_derived_functions or reference_report.all_symbols
        )
        target_func_map = ArtifactMatcher.build_function_map(
            target_report.symbol_derived_functions or target_report.all_symbols
        )

        # Compare functions present in both
        for key_tuple, ref_func in ref_func_map.items():
            if key_tuple in target_func_map:
                target_func = target_func_map[key_tuple]

                # Size change check
                if ref_func.size != target_func.size:
                    function_deltas.append(
                        FunctionDelta(
                            delta_type="FUNCTION_SIZE_CHANGED",
                            function_name=ref_func.name,
                            details=(
                                f"Function '{ref_func.name}' size changed "
                                f"from {ref_func.size} to {target_func.size} bytes."
                            ),
                            old_digest=None,
                            new_digest=None,
                        )
                    )

                # Raw byte code fingerprint comparison
                ref_code_digest = FunctionFingerprinter.compute_function_code_digest(
                    func=ref_func,
                    reader=reference_reader,
                    sections=reference_report.sections,
                )
                target_code_digest = FunctionFingerprinter.compute_function_code_digest(
                    func=target_func,
                    reader=target_reader,
                    sections=target_report.sections,
                )

                if ref_code_digest.warning:
                    warnings.append(
                        f"Reference function '{ref_func.name}': {ref_code_digest.warning}"
                    )
                if target_code_digest.warning:
                    warnings.append(
                        f"Target function '{target_func.name}': {target_code_digest.warning}"
                    )

                if (
                    ref_code_digest.is_valid_range
                    and target_code_digest.is_valid_range
                    and not ref_code_digest.is_zero_size
                    and not target_code_digest.is_zero_size
                    and ref_code_digest.raw_bytes_sha256
                    and target_code_digest.raw_bytes_sha256
                ):
                    if ref_code_digest.raw_bytes_sha256 != target_code_digest.raw_bytes_sha256:
                        function_deltas.append(
                            FunctionDelta(
                                delta_type="MODIFIED_FUNCTION_CODE",
                                function_name=ref_func.name,
                                details=(
                                    f"Function '{ref_func.name}' raw byte code SHA-256 "
                                    f"digest modified."
                                ),
                                old_digest=ref_code_digest.raw_bytes_sha256,
                                new_digest=target_code_digest.raw_bytes_sha256,
                            )
                        )

        # Added functions in target
        for key_tuple, target_func in target_func_map.items():
            if key_tuple not in ref_func_map:
                target_code_digest = FunctionFingerprinter.compute_function_code_digest(
                    func=target_func,
                    reader=target_reader,
                    sections=target_report.sections,
                )
                function_deltas.append(
                    FunctionDelta(
                        delta_type="ADDED_FUNCTION",
                        function_name=target_func.name,
                        details=f"New function '{target_func.name}' present in target artifact.",
                        old_digest=None,
                        new_digest=target_code_digest.raw_bytes_sha256,
                    )
                )

        # Removed functions from reference (SUPPRESSED if inventory is PARTIAL or UNAVAILABLE)
        for key_tuple, ref_func in ref_func_map.items():
            if key_tuple not in target_func_map:
                if not is_partial_comparison:
                    ref_code_digest = FunctionFingerprinter.compute_function_code_digest(
                        func=ref_func,
                        reader=reference_reader,
                        sections=reference_report.sections,
                    )
                    function_deltas.append(
                        FunctionDelta(
                            delta_type="REMOVED_FUNCTION",
                            function_name=ref_func.name,
                            details=(
                                f"Function '{ref_func.name}' missing from target artifact "
                                f"under COMPLETE inventory."
                            ),
                            old_digest=ref_code_digest.raw_bytes_sha256,
                            new_digest=None,
                        )
                    )

        # 7. Dynamic Library Dependencies (DT_NEEDED)
        dependency_deltas: List[DependencyDelta] = []
        ref_libs = set(reference_report.imported_libraries)
        target_libs = set(target_report.imported_libraries)

        for lib in target_libs - ref_libs:
            dependency_deltas.append(
                DependencyDelta(
                    delta_type="ADDED_DEPENDENCY",
                    library_name=lib,
                    details=f"Target artifact introduced new dynamic library dependency: '{lib}'.",
                )
            )

        for lib in ref_libs - target_libs:
            dependency_deltas.append(
                DependencyDelta(
                    delta_type="REMOVED_DEPENDENCY",
                    library_name=lib,
                    details=f"Target artifact removed dynamic library dependency: '{lib}'.",
                )
            )

        # 8. Granular W+X Security Observation Deltas
        security_observation_deltas: List[SecurityObservationDelta] = []

        ref_wx_sec = reference_report.has_wx_sections
        target_wx_sec = target_report.has_wx_sections
        if not ref_wx_sec and target_wx_sec:
            security_observation_deltas.append(
                SecurityObservationDelta(
                    observation_type="WX_SECTION_INTRODUCED",
                    target_name="sections",
                    details=(
                        "Target artifact introduced one or more W+X sections "
                        "(SHF_WRITE + SHF_EXECINSTR)."
                    ),
                )
            )
        elif ref_wx_sec and not target_wx_sec:
            security_observation_deltas.append(
                SecurityObservationDelta(
                    observation_type="WX_SECTION_REMOVED",
                    target_name="sections",
                    details="Target artifact eliminated W+X sections present in reference.",
                )
            )

        ref_wx_seg = reference_report.has_wx_load_segments
        target_wx_seg = target_report.has_wx_load_segments
        if not ref_wx_seg and target_wx_seg:
            security_observation_deltas.append(
                SecurityObservationDelta(
                    observation_type="WX_LOAD_SEGMENT_INTRODUCED",
                    target_name="load_segments",
                    details=(
                        "Target artifact introduced one or more W+X PT_LOAD segments (PF_W + PF_X)."
                    ),
                )
            )
        elif ref_wx_seg and not target_wx_seg:
            security_observation_deltas.append(
                SecurityObservationDelta(
                    observation_type="WX_LOAD_SEGMENT_REMOVED",
                    target_name="load_segments",
                    details="Target artifact eliminated W+X load segments present in reference.",
                )
            )

        result = ComparisonResult(
            reference_artifact_digest=reference_digest,
            target_artifact_digest=target_digest,
            digest_matches=digest_matches,
            reference_completeness=ref_completeness,
            target_completeness=target_completeness,
            is_partial_comparison=is_partial_comparison,
            structural_deltas=structural_deltas,
            function_deltas=function_deltas,
            dependency_deltas=dependency_deltas,
            security_observation_deltas=security_observation_deltas,
            warnings=warnings,
        )

        return result.sort_deltas()
