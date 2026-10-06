"""
Unit Tests for SBOM Comparison Engine (V08-V12, V18, V19, V29).
"""

from provenanceguard.core.verification.sbom_compare import SBOMComparisonEngine
from provenanceguard.core.verification.sbom_models import (
    ChecksumEvidence,
    LicenseEvidence,
    PackageDeltaType,
    PackageEvidence,
    PackageIdentity,
    SBOMInventoryCompleteness,
    SBOMReport,
)


def test_version_changed_upgrade():
    """V08: VERSION_CHANGED upgrade."""
    engine = SBOMComparisonEngine()

    ref = SBOMReport(
        spec_version="SPDX-2.2",
        format_type="SPDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="SPDX",
                source_version="SPDX-2.2",
                identity=PackageIdentity.from_purl("pkg:pypi/requests@2.31.0"),
                name="requests",
                version="2.31.0",
            )
        ],
    )

    tar = SBOMReport(
        spec_version="SPDX-2.2",
        format_type="SPDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="SPDX",
                source_version="SPDX-2.2",
                identity=PackageIdentity.from_purl("pkg:pypi/requests@2.32.0"),
                name="requests",
                version="2.32.0",
            )
        ],
    )

    result = engine.compare(ref, tar)
    assert len(result.package_deltas) == 1
    assert result.package_deltas[0].delta_type == PackageDeltaType.VERSION_CHANGED
    assert result.package_deltas[0].old_value == "2.31.0"
    assert result.package_deltas[0].new_value == "2.32.0"


def test_version_changed_downgrade():
    """V09: VERSION_CHANGED downgrade."""
    engine = SBOMComparisonEngine()

    ref = SBOMReport(
        spec_version="SPDX-2.2",
        format_type="SPDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="SPDX",
                source_version="SPDX-2.2",
                identity=PackageIdentity.from_purl("pkg:pypi/requests@2.32.0"),
                name="requests",
                version="2.32.0",
            )
        ],
    )

    tar = SBOMReport(
        spec_version="SPDX-2.2",
        format_type="SPDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="SPDX",
                source_version="SPDX-2.2",
                identity=PackageIdentity.from_purl("pkg:pypi/requests@2.31.0"),
                name="requests",
                version="2.31.0",
            )
        ],
    )

    result = engine.compare(ref, tar)
    assert len(result.package_deltas) == 1
    assert result.package_deltas[0].delta_type == PackageDeltaType.VERSION_CHANGED
    assert result.package_deltas[0].old_value == "2.32.0"
    assert result.package_deltas[0].new_value == "2.31.0"


def test_added_package_completeness_governance():
    """V10: ADDED_PACKAGE completeness governance."""
    engine = SBOMComparisonEngine()

    ref_complete = SBOMReport(
        spec_version="1.4",
        format_type="CYCLONEDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[],
    )
    ref_partial = SBOMReport(
        spec_version="1.4",
        format_type="CYCLONEDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.PARTIAL,
        packages=[],
    )

    tar = SBOMReport(
        spec_version="1.4",
        format_type="CYCLONEDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="CYCLONEDX",
                source_version="1.4",
                identity=PackageIdentity.from_purl("pkg:npm/express@4.17.1"),
                name="express",
                version="4.17.1",
            )
        ],
    )

    # Reference COMPLETE -> ADDED_PACKAGE emitted
    res1 = engine.compare(ref_complete, tar)
    assert any(d.delta_type == PackageDeltaType.ADDED_PACKAGE for d in res1.package_deltas)

    # Reference PARTIAL -> ADDED_PACKAGE suppressed
    res2 = engine.compare(ref_partial, tar)
    assert not any(d.delta_type == PackageDeltaType.ADDED_PACKAGE for d in res2.package_deltas)
    assert any("suppressed from ADDED_PACKAGE" in w for w in res2.warnings)


def test_removed_package_completeness_governance():
    """V11: REMOVED_PACKAGE completeness governance."""
    engine = SBOMComparisonEngine()

    ref = SBOMReport(
        spec_version="1.4",
        format_type="CYCLONEDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="CYCLONEDX",
                source_version="1.4",
                identity=PackageIdentity.from_purl("pkg:npm/express@4.17.1"),
                name="express",
                version="4.17.1",
            )
        ],
    )

    tar_complete = SBOMReport(
        spec_version="1.4",
        format_type="CYCLONEDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[],
    )
    tar_partial = SBOMReport(
        spec_version="1.4",
        format_type="CYCLONEDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.PARTIAL,
        packages=[],
    )

    # Target COMPLETE -> REMOVED_PACKAGE emitted
    res1 = engine.compare(ref, tar_complete)
    assert any(d.delta_type == PackageDeltaType.REMOVED_PACKAGE for d in res1.package_deltas)

    # Target PARTIAL -> REMOVED_PACKAGE suppressed
    res2 = engine.compare(ref, tar_partial)
    assert not any(d.delta_type == PackageDeltaType.REMOVED_PACKAGE for d in res2.package_deltas)
    assert any("suppressed from REMOVED_PACKAGE" in w for w in res2.warnings)


def test_completeness_decision_matrix_all_combinations():
    """V12: PARTIAL/UNKNOWN completeness behavior across all combinations."""
    engine = SBOMComparisonEngine()

    def make_report(completeness, pkgs):
        return SBOMReport(
            spec_version="1.4",
            format_type="CYCLONEDX_JSON",
            inventory_completeness=completeness,
            packages=[
                PackageEvidence(
                    source_format="CYCLONEDX",
                    source_version="1.4",
                    identity=PackageIdentity.from_purl(f"pkg:npm/{name}@1.0"),
                    name=name,
                    version="1.0",
                )
                for name in pkgs
            ],
        )

    # 1. COMPLETE vs COMPLETE -> Added YES, Removed YES
    r1 = engine.compare(
        make_report(SBOMInventoryCompleteness.COMPLETE, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.COMPLETE, ["PkgB"]),
    )
    d1 = {d.delta_type for d in r1.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE in d1 and PackageDeltaType.REMOVED_PACKAGE in d1

    # 2. COMPLETE vs PARTIAL -> Added YES, Removed NO
    r2 = engine.compare(
        make_report(SBOMInventoryCompleteness.COMPLETE, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.PARTIAL, ["PkgB"]),
    )
    d2 = {d.delta_type for d in r2.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE in d2 and PackageDeltaType.REMOVED_PACKAGE not in d2

    # 3. PARTIAL vs COMPLETE -> Added NO, Removed YES
    r3 = engine.compare(
        make_report(SBOMInventoryCompleteness.PARTIAL, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.COMPLETE, ["PkgB"]),
    )
    d3 = {d.delta_type for d in r3.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE not in d3 and PackageDeltaType.REMOVED_PACKAGE in d3

    # 4. PARTIAL vs PARTIAL -> Added NO, Removed NO
    r4 = engine.compare(
        make_report(SBOMInventoryCompleteness.PARTIAL, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.PARTIAL, ["PkgB"]),
    )
    d4 = {d.delta_type for d in r4.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE not in d4 and PackageDeltaType.REMOVED_PACKAGE not in d4

    # 5. UNKNOWN vs COMPLETE -> Added NO, Removed YES
    r5 = engine.compare(
        make_report(SBOMInventoryCompleteness.UNKNOWN, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.COMPLETE, ["PkgB"]),
    )
    d5 = {d.delta_type for d in r5.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE not in d5 and PackageDeltaType.REMOVED_PACKAGE in d5

    # 6. COMPLETE vs UNKNOWN -> Added YES, Removed NO
    r6 = engine.compare(
        make_report(SBOMInventoryCompleteness.COMPLETE, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.UNKNOWN, ["PkgB"]),
    )
    d6 = {d.delta_type for d in r6.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE in d6 and PackageDeltaType.REMOVED_PACKAGE not in d6

    # 7. UNKNOWN vs UNKNOWN -> Added NO, Removed NO
    r7 = engine.compare(
        make_report(SBOMInventoryCompleteness.UNKNOWN, ["PkgA"]),
        make_report(SBOMInventoryCompleteness.UNKNOWN, ["PkgB"]),
    )
    d7 = {d.delta_type for d in r7.package_deltas}
    assert PackageDeltaType.ADDED_PACKAGE not in d7 and PackageDeltaType.REMOVED_PACKAGE not in d7


def test_checksum_mismatch_semantics():
    """V18: Checksum mismatch semantics."""
    engine = SBOMComparisonEngine()

    ref_pkg = PackageEvidence(
        source_format="SPDX",
        source_version="SPDX-2.2",
        identity=PackageIdentity.from_purl("pkg:pypi/cryptography@41.0.0"),
        name="cryptography",
        version="41.0.0",
        checksums=[ChecksumEvidence(normalized_algorithm="SHA256", digest="aaa")],
    )
    tar_pkg = PackageEvidence(
        source_format="SPDX",
        source_version="SPDX-2.2",
        identity=PackageIdentity.from_purl("pkg:pypi/cryptography@41.0.0"),
        name="cryptography",
        version="41.0.0",
        checksums=[ChecksumEvidence(normalized_algorithm="SHA256", digest="bbb")],
    )

    result = engine.compare(
        SBOMReport(
            spec_version="SPDX-2.2",
            format_type="SPDX_JSON",
            inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
            packages=[ref_pkg],
        ),
        SBOMReport(
            spec_version="SPDX-2.2",
            format_type="SPDX_JSON",
            inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
            packages=[tar_pkg],
        ),
    )

    assert len(result.package_deltas) == 1
    assert result.package_deltas[0].delta_type == PackageDeltaType.CHECKSUM_MISMATCH


def test_multiple_checksum_handling():
    """V19: Multiple checksum handling."""
    engine = SBOMComparisonEngine()

    ref_pkg = PackageEvidence(
        source_format="SPDX",
        source_version="SPDX-2.2",
        identity=PackageIdentity.from_purl("pkg:pypi/cryptography@41.0.0"),
        name="cryptography",
        version="41.0.0",
        checksums=[
            ChecksumEvidence(normalized_algorithm="SHA256", digest="aaa"),
            ChecksumEvidence(normalized_algorithm="SHA512", digest="ccc"),
        ],
    )
    tar_pkg = PackageEvidence(
        source_format="SPDX",
        source_version="SPDX-2.2",
        identity=PackageIdentity.from_purl("pkg:pypi/cryptography@41.0.0"),
        name="cryptography",
        version="41.0.0",
        checksums=[
            ChecksumEvidence(normalized_algorithm="SHA256", digest="bbb"),
            ChecksumEvidence(normalized_algorithm="SHA512", digest="ccc"),
        ],
    )

    result = engine.compare(
        SBOMReport(
            spec_version="SPDX-2.2",
            format_type="SPDX_JSON",
            inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
            packages=[ref_pkg],
        ),
        SBOMReport(
            spec_version="SPDX-2.2",
            format_type="SPDX_JSON",
            inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
            packages=[tar_pkg],
        ),
    )

    # SHA256 differs -> CHECKSUM_MISMATCH, SHA512 matches -> 0 mismatch for SHA512
    assert len(result.package_deltas) == 1
    assert result.package_deltas[0].old_value == "aaa"
    assert result.package_deltas[0].new_value == "bbb"


def test_deterministic_repeated_comparison():
    """V29: Deterministic repeated comparison."""
    engine = SBOMComparisonEngine()

    ref = SBOMReport(
        spec_version="SPDX-2.2",
        format_type="SPDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="SPDX",
                source_version="SPDX-2.2",
                identity=PackageIdentity.from_purl("pkg:pypi/requests@2.31.0"),
                name="requests",
                version="2.31.0",
                licenses=LicenseEvidence(license_declared="Apache-2.0"),
            )
        ],
    )
    tar = SBOMReport(
        spec_version="SPDX-2.2",
        format_type="SPDX_JSON",
        inventory_completeness=SBOMInventoryCompleteness.COMPLETE,
        packages=[
            PackageEvidence(
                source_format="SPDX",
                source_version="SPDX-2.2",
                identity=PackageIdentity.from_purl("pkg:pypi/requests@2.32.0"),
                name="requests",
                version="2.32.0",
                licenses=LicenseEvidence(license_declared="MIT"),
            )
        ],
    )

    res1 = engine.compare(ref, tar)
    res2 = engine.compare(ref, tar)

    assert res1.model_dump_json() == res2.model_dump_json()
