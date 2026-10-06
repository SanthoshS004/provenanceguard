"""
Security Boundary & Adversarial Tests for SBOM Parser & Resource Defenses (V20-V27, V30).
"""

import json
import os
import socket
import subprocess
import urllib.request

import pytest

from provenanceguard.analyzers.sbom.parser import (
    MAX_COMPONENTS_COUNT,
    MAX_SBOM_SIZE,
    SBOMAnalyzer,
    SBOMParserError,
    sanitize_raw_extension_data,
    validate_json_structural_depth,
)
from provenanceguard.core.verification.sbom_compare import SBOMComparisonEngine


def test_sbom_oversized_payload_rejected():
    """V24: Oversized document rejection."""
    analyzer = SBOMAnalyzer()
    oversized_bytes = b" " * (MAX_SBOM_SIZE + 10)

    with pytest.raises(SBOMParserError) as exc:
        analyzer.parse_sbom(oversized_bytes)
    assert exc.value.error_code == "RESOURCE_LIMIT_EXCEEDED"
    assert "exceeds limit" in str(exc.value)


def test_sbom_excessive_components_count_rejected():
    """V25: Oversized array/object component count rejection."""
    analyzer = SBOMAnalyzer()
    pkgs = [{"name": f"pkg_{i}", "versionInfo": "1.0"} for i in range(MAX_COMPONENTS_COUNT + 5)]
    spdx_json = json.dumps({"spdxVersion": "SPDX-2.2", "packages": pkgs}).encode("utf-8")

    with pytest.raises(SBOMParserError) as exc:
        analyzer.parse_sbom(spdx_json)
    assert exc.value.error_code == "RESOURCE_LIMIT_EXCEEDED"


def test_extension_data_resource_limits():
    """V20: Extension-data resource limits."""
    # Nesting depth > 5 should be truncated
    deep_ext = {"a": {"b": {"c": {"d": {"e": {"f": "too_deep"}}}}}}
    sanitized = sanitize_raw_extension_data(deep_ext)
    assert "f" not in str(sanitized)

    # String size > 16 KiB should be truncated
    huge_str = "x" * 20000
    sanitized_str = sanitize_raw_extension_data({"key": huge_str})
    assert len(sanitized_str["key"]) == 16384


def test_json_structural_depth_pre_scanner_escaped_quotes_and_brackets():
    """V21: JSON-aware depth scanner correctness with escaped string content."""
    complex_valid_json = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [
                {
                    "name": "pkg_with_tricky_string",
                    "comment": (
                        'This string has {"brackets": "[and] {braces}"} and \\"escaped quotes\\"'
                    ),
                }
            ],
        }
    )

    validate_json_structural_depth(complex_valid_json, max_depth=10)

    deep_json = "{" + '"a":{' * 12 + '"val":1' + "}" * 12 + "}"
    with pytest.raises(SBOMParserError) as exc:
        validate_json_structural_depth(deep_json, max_depth=10)
    assert exc.value.error_code == "RESOURCE_LIMIT_EXCEEDED"


def test_malformed_json_and_utf8_rejected():
    """V22: Malformed JSON and UTF-8 rejection."""
    analyzer = SBOMAnalyzer()

    with pytest.raises(SBOMParserError) as exc1:
        analyzer.parse_sbom(b"{name: [malformed json")
    assert exc1.value.error_code in ("INVALID_DOCUMENT", "RESOURCE_LIMIT_EXCEEDED")

    with pytest.raises(SBOMParserError) as exc2:
        analyzer.parse_sbom(b"\x80\x81\x82\x83\x84")
    assert exc2.value.error_code == "INVALID_DOCUMENT"


def test_unsupported_spec_versions_rejected():
    """V23: Unsupported specification version rejection."""
    analyzer = SBOMAnalyzer()

    spdx_21 = json.dumps({"spdxVersion": "SPDX-2.1", "packages": []}).encode("utf-8")
    with pytest.raises(SBOMParserError) as exc1:
        analyzer.parse_sbom(spdx_21)
    assert exc1.value.error_code == "UNSUPPORTED_VERSION"

    cdx_13 = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.3", "components": []}).encode(
        "utf-8"
    )
    with pytest.raises(SBOMParserError) as exc2:
        analyzer.parse_sbom(cdx_13)
    assert exc2.value.error_code == "UNSUPPORTED_VERSION"


def test_zero_subprocess_execution_boundary(monkeypatch):
    """V26: Zero subprocess execution boundary test."""

    def forbidden_call(*args, **kwargs):
        raise AssertionError(
            "SECURITY VIOLATION: Subprocess execution attempted during SBOM analysis!"
        )

    monkeypatch.setattr(subprocess, "Popen", forbidden_call)
    monkeypatch.setattr(subprocess, "run", forbidden_call)
    monkeypatch.setattr(os, "system", forbidden_call)

    analyzer = SBOMAnalyzer()
    spdx_json = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [{"name": "safe_pkg", "versionInfo": "1.0"}],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(spdx_json)
    assert report.packages[0].name == "safe_pkg"


def test_zero_network_execution_boundary(monkeypatch):
    """V27: Zero network execution boundary test."""

    def forbidden_socket(*args, **kwargs):
        raise AssertionError(
            "SECURITY VIOLATION: Network socket access attempted during SBOM analysis!"
        )

    def forbidden_urlopen(*args, **kwargs):
        raise AssertionError("SECURITY VIOLATION: HTTP request attempted during SBOM analysis!")

    monkeypatch.setattr(socket, "socket", forbidden_socket)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden_urlopen)

    analyzer = SBOMAnalyzer()
    spdx_json = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [{"name": "network_free_pkg", "versionInfo": "1.0"}],
        }
    ).encode("utf-8")

    report = analyzer.parse_sbom(spdx_json)
    assert report.packages[0].name == "network_free_pkg"


def test_evidence_only_boundary():
    """V30: Evidence-only boundary test."""
    analyzer = SBOMAnalyzer()
    engine = SBOMComparisonEngine()

    doc1 = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [{"name": "requests", "versionInfo": "2.31.0"}],
        }
    ).encode("utf-8")
    doc2 = json.dumps(
        {
            "spdxVersion": "SPDX-2.2",
            "packages": [{"name": "requests", "versionInfo": "2.32.0"}],
        }
    ).encode("utf-8")

    rep1 = analyzer.parse_sbom(doc1)
    rep2 = analyzer.parse_sbom(doc2)
    result = engine.compare(rep1, rep2)

    # Must contain ONLY objective evidence, NO risk_score, NO PASS/BLOCK decisions
    assert not hasattr(result, "risk_score")
    assert not hasattr(result, "decision")
    assert hasattr(result, "package_deltas")
    assert len(result.package_deltas) == 1
