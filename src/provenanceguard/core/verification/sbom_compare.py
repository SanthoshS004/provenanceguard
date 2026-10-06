"""
Deterministic Package Inventory Evidence Comparison Engine for SBOM Reports.
Governed by explicit completeness absence rules and identity/version separation.
"""

from typing import Dict, List

from provenanceguard.core.verification.sbom_models import (
    PackageDelta,
    PackageDeltaType,
    PackageEvidence,
    SBOMComparisonResult,
    SBOMInventoryCompleteness,
    SBOMReport,
)


class SBOMComparisonEngine:
    """
    100% Deterministic Engine for comparing reference vs target SBOM package inventories.
    Produces objective package deltas with zero risk calculation and zero PASS/BLOCK verdicts.
    """

    def compare(
        self,
        reference_sbom: SBOMReport,
        target_sbom: SBOMReport,
        reference_digest: str = "ref_sha256",
        target_digest: str = "target_sha256",
    ) -> SBOMComparisonResult:
        """
        Compares reference and target SBOM package reports using canonical package identities.
        """
        ref_comp = reference_sbom.inventory_completeness
        target_comp = target_sbom.inventory_completeness

        # Completeness Decision Matrix
        can_infer_added = ref_comp == SBOMInventoryCompleteness.COMPLETE
        can_infer_removed = target_comp == SBOMInventoryCompleteness.COMPLETE

        ref_packages: Dict[str, PackageEvidence] = {}
        for p in reference_sbom.packages:
            ref_packages[p.identity.canonical_key] = p

        target_packages: Dict[str, PackageEvidence] = {}
        for p in target_sbom.packages:
            target_packages[p.identity.canonical_key] = p

        deltas: List[PackageDelta] = []
        warnings: List[str] = []

        # 1. Evaluate Matched Identities (Present in both reference and target)
        matched_keys = set(ref_packages.keys()).intersection(set(target_packages.keys()))

        for key in sorted(matched_keys):
            ref_p = ref_packages[key]
            tar_p = target_packages[key]

            # A. Version Shift Check
            if ref_p.version != tar_p.version:
                if ref_p.version is not None and tar_p.version is not None:
                    deltas.append(
                        PackageDelta(
                            delta_type=PackageDeltaType.VERSION_CHANGED,
                            package_name=tar_p.name,
                            purl=tar_p.purl or ref_p.purl,
                            details=(
                                f"Package '{tar_p.name}' version changed from "
                                f"'{ref_p.version}' to '{tar_p.version}'"
                            ),
                            old_value=ref_p.version,
                            new_value=tar_p.version,
                        )
                    )

            # B. License Shift Check
            ref_lic_str = ref_p.licenses.canonical_string()
            tar_lic_str = tar_p.licenses.canonical_string()

            if ref_lic_str != tar_lic_str:
                deltas.append(
                    PackageDelta(
                        delta_type=PackageDeltaType.LICENSE_CHANGED,
                        package_name=tar_p.name,
                        purl=tar_p.purl or ref_p.purl,
                        details=(
                            f"Package '{tar_p.name}' license changed from "
                            f"'{ref_lic_str}' to '{tar_lic_str}'"
                        ),
                        old_value=ref_lic_str,
                        new_value=tar_lic_str,
                    )
                )

            # C. Checksum Mismatch Check
            # Checksums are matched ONLY when both sides supply the same normalized algorithm
            ref_chk_map = {c.normalized_algorithm: c.digest for c in ref_p.checksums}
            tar_chk_map = {c.normalized_algorithm: c.digest for c in tar_p.checksums}

            common_algs = set(ref_chk_map.keys()).intersection(set(tar_chk_map.keys()))
            for alg in sorted(common_algs):
                if ref_chk_map[alg] != tar_chk_map[alg]:
                    deltas.append(
                        PackageDelta(
                            delta_type=PackageDeltaType.CHECKSUM_MISMATCH,
                            package_name=tar_p.name,
                            purl=tar_p.purl or ref_p.purl,
                            details=(
                                f"Package '{tar_p.name}' checksum mismatch for algorithm {alg}: "
                                f"reference '{ref_chk_map[alg]}' vs target '{tar_chk_map[alg]}'"
                            ),
                            old_value=ref_chk_map[alg],
                            new_value=tar_chk_map[alg],
                        )
                    )

        # 2. Evaluate Unmatched Target Packages (Potential ADDED_PACKAGE)
        unmatched_target_keys = set(target_packages.keys()) - set(ref_packages.keys())
        for key in sorted(unmatched_target_keys):
            tar_p = target_packages[key]
            if can_infer_added:
                deltas.append(
                    PackageDelta(
                        delta_type=PackageDeltaType.ADDED_PACKAGE,
                        package_name=tar_p.name,
                        purl=tar_p.purl,
                        details=f"Package '{tar_p.name}' added in target inventory",
                        old_value=None,
                        new_value=tar_p.version,
                    )
                )
            else:
                warnings.append(
                    f"Package '{tar_p.name}' present in target but suppressed from ADDED_PACKAGE "
                    f"because reference inventory completeness is '{ref_comp.value}'"
                )

        # 3. Evaluate Unmatched Reference Packages (Potential REMOVED_PACKAGE)
        unmatched_ref_keys = set(ref_packages.keys()) - set(target_packages.keys())
        for key in sorted(unmatched_ref_keys):
            ref_p = ref_packages[key]
            if can_infer_removed:
                deltas.append(
                    PackageDelta(
                        delta_type=PackageDeltaType.REMOVED_PACKAGE,
                        package_name=ref_p.name,
                        purl=ref_p.purl,
                        details=f"Package '{ref_p.name}' removed in target inventory",
                        old_value=ref_p.version,
                        new_value=None,
                    )
                )
            else:
                warnings.append(
                    f"Package '{ref_p.name}' missing in target but suppressed from REMOVED_PACKAGE "
                    f"because target inventory completeness is '{target_comp.value}'"
                )

        result = SBOMComparisonResult(
            reference_sbom_digest=reference_digest,
            target_sbom_digest=target_digest,
            reference_completeness=ref_comp,
            target_completeness=target_comp,
            package_deltas=deltas,
            warnings=warnings,
        )

        return result.sort_deltas()
