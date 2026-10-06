"""
Unit Tests for SPDX and CycloneDX SBOM Parser & Normalizer (V01-V07, V13-V17, V28).
"""

import json

from provenanceguard.analyzers.sbom.parser import SBOMAnalyzer
from provenanceguard.core.verification.sbom_models import IdentityStatus, PackageIdentity


def test_spdx_22_parsing():
    """V01: SPDX 2.2 parsing."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "sample-spdx",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Pkg1",
                    "name": "requests",
                    "versionInfo": "2.31.0",
                    "licenseDeclared": "Apache-2.0",
                    "licenseConcluded": "Apache-2.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/requests@2.31.0",
                        }
                    ],
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "aaa111"}],
                }
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    assert report.spec_version == "SPDX-2.2"
    assert len(report.packages) == 1
    assert report.packages[0].name == "requests"


def test_spdx_23_parsing():
    """V02: SPDX 2.3 parsing."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "sample-spdx-23",
            "packages": [
                {
                    "SPDXID": "SPDXRef-Pkg2",
                    "name": "urllib3",
                    "versionInfo": "1.26.5",
                    "licenseDeclared": "MIT",
                    "licenseConcluded": "NOASSERTION",
                    "checksums": [{"algorithm": "sha-256", "checksumValue": "bbb222"}],
                }
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    assert report.spec_version == "SPDX-2.3"
    assert report.packages[0].name == "urllib3"


def test_cyclonedx_14_parsing():
    """V03: CycloneDX 1.4 parsing."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "bom-ref": "comp-1",
                    "name": "express",
                    "version": "4.17.1",
                    "purl": "pkg:npm/express@4.17.1",
                    "licenses": [{"license": {"id": "MIT"}}],
                    "hashes": [{"alg": "SHA-256", "content": "ccc333"}],
                }
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    assert report.spec_version == "1.4"
    assert report.packages[0].name == "express"


def test_cyclonedx_15_parsing():
    """V04: CycloneDX 1.5 parsing."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {
                    "bom-ref": "comp-2",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/%40lodash/lodash@4.17.21",
                    "licenses": [{"expression": "MIT"}],
                }
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    assert report.spec_version == "1.5"
    assert report.packages[0].name == "lodash"


def test_purl_identity_normalization():
    """V05: PURL identity normalization."""
    purl1 = "pkg:pypi/requests@2.31.0?env=prod#sub"
    purl2 = "pkg:pypi/requests@2.32.0?env=prod#sub"

    id1 = PackageIdentity.from_purl(purl1)
    id2 = PackageIdentity.from_purl(purl2)

    assert id1 is not None and id2 is not None
    assert id1.canonical_key == id2.canonical_key
    assert "@" not in id1.canonical_key
    assert id1.canonical_key == "pkg:pypi/requests?env=prod#sub"


def test_fallback_identity_normalization():
    """V06: Fallback identity normalization."""
    id1 = PackageIdentity.from_name_supplier("libssl", "OpenSSL Project")
    id2 = PackageIdentity.from_name_supplier("libssl", "OpenSSL Project")

    assert id1.canonical_key == id2.canonical_key
    assert id1.canonical_key == "fallback:openssl project/libssl"


def test_identity_version_separation():
    """V07: Identity/version separation."""
    id1 = PackageIdentity.from_purl("pkg:npm/react@17.0.2")
    id2 = PackageIdentity.from_purl("pkg:npm/react@18.2.0")

    assert id1.canonical_key == id2.canonical_key
    assert id1.canonical_key == "pkg:npm/react"


def test_duplicate_identity_handling():
    """V13: Duplicate identity handling."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {"name": "requests", "versionInfo": "2.31.0"},
                {"name": "requests", "versionInfo": "2.31.0"},
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    assert len(report.packages) == 2
    assert report.packages[0].identity_status == IdentityStatus.UNIQUE
    assert report.packages[1].identity_status == IdentityStatus.DUPLICATE


def test_ambiguous_identity_handling():
    """V14: Ambiguous identity handling."""
    id_no_supplier = PackageIdentity.from_name_supplier("common-utils", None)
    assert id_no_supplier.canonical_key == "name:common-utils"


def test_license_declared_concluded_info_from_files_preservation():
    """V15: licenseDeclared/licenseConcluded/licenseInfoFromFiles preservation."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {
                    "name": "pkg_lic",
                    "licenseDeclared": "Apache-2.0",
                    "licenseConcluded": "GPL-3.0",
                    "licenseInfoFromFiles": ["MIT", "BSD-3-Clause"],
                }
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    lic = report.packages[0].licenses
    assert lic.license_declared == "Apache-2.0"
    assert lic.license_concluded == "GPL-3.0"
    assert lic.license_info_from_files == ["MIT", "BSD-3-Clause"]


def test_spdx_license_special_values_none_noassertion():
    """V16: NONE/NOASSERTION preservation."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {
                    "name": "pkg_none",
                    "licenseDeclared": "NONE",
                    "licenseConcluded": "NONE",
                },
                {
                    "name": "pkg_noassert",
                    "licenseDeclared": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                },
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    assert report.packages[0].licenses.is_none is True
    assert report.packages[0].licenses.canonical_string() == "NONE"
    assert report.packages[1].licenses.is_noassertion is True
    assert report.packages[1].licenses.canonical_string() == "NOASSERTION"


def test_checksum_algorithm_normalization():
    """V17: Checksum algorithm normalization."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {
                    "name": "pkg_chk",
                    "checksums": [
                        {"algorithm": "sha-256", "checksumValue": "aaa"},
                        {"algorithm": "SHA_512", "checksumValue": "bbb"},
                        {"algorithm": "md5", "checksumValue": "ccc"},
                    ],
                }
            ],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(doc)
    chks = report.packages[0].checksums
    algs = {c.normalized_algorithm for c in chks}
    assert algs == {"SHA256", "SHA512", "MD5"}


def test_deterministic_repeated_normalization():
    """V28: Deterministic repeated normalization."""
    analyzer = SBOMAnalyzer()
    doc = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {
                    "name": "pkg_rep",
                    "versionInfo": "1.0.0",
                    "checksums": [{"algorithm": "SHA256", "checksumValue": "abc"}],
                }
            ],
        }
    ).encode("utf-8")

    report1 = analyzer.parse_sbom(doc)
    report2 = analyzer.parse_sbom(doc)

    assert report1.model_dump_json() == report2.model_dump_json()
