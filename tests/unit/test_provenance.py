"""
Unit Tests for in-toto Statement v1 & SLSA v1.2 Provenance Validator.
"""

import pytest

from provenanceguard.core.verification.exceptions import ProvenanceValidationError
from provenanceguard.core.verification.provenance import (
    MAX_BYPRODUCTS_COUNT,
    MAX_JSON_NESTING_DEPTH,
    MAX_RESOLVED_DEPENDENCIES_COUNT,
    MAX_SUBJECTS_COUNT,
    SLSAProvenanceValidator,
)


@pytest.fixture
def valid_slsa_statement():
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [
            {
                "name": "release-v1.0.tar.gz",
                "digest": {
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                },
                "custom_subject_attr": "subject_ext_val",
            }
        ],
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://actions.github.io/buildtypes/v1",
                "externalParameters": {
                    "repository": "https://github.com/example/repo",
                    "ref": "refs/heads/main",
                },
                "internalParameters": {
                    "runner": "ubuntu-22.04",
                },
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/example/dep@v1.0.0",
                        "digest": {
                            "sha256": "11111111111111111111111111111111"
                            "11111111111111111111111111111111"
                        },
                    }
                ],
                "custom_build_def_field": "build_def_ext",
            },
            "runDetails": {
                "builder": {"id": "https://github.com/actions/runner"},
                "metadata": {"invocationId": "12345"},
                "byproducts": [{"name": "build.log"}],
                "custom_run_details_field": "run_details_ext",
            },
            "custom_predicate_field": "pred_ext",
        },
        "custom_statement_field": "stmt_ext",
    }


def test_valid_slsa_provenance_validation(valid_slsa_statement):
    validator = SLSAProvenanceValidator()
    report = validator.validate_statement(
        valid_slsa_statement,
        target_artifact_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )

    assert report.statement_version == "https://in-toto.io/Statement/v1"
    assert report.predicate_type == "https://slsa.dev/provenance/v1"
    assert report.build_definition.build_type == "https://actions.github.io/buildtypes/v1"
    assert (
        report.build_definition.external_parameters["repository"]
        == "https://github.com/example/repo"
    )
    assert report.build_definition.extension_evidence["custom_build_def_field"] == "build_def_ext"

    assert report.run_details.builder_id == "https://github.com/actions/runner"
    assert report.run_details.extension_evidence["custom_run_details_field"] == "run_details_ext"

    # Check subject correlation
    assert report.subject_correlation.matching_mode == "EXACT_ONE_MATCH"
    assert report.subject_correlation.subject_digest_match is True
    assert report.subject_correlation.matching_subject_count == 1
    assert len(report.subject_correlation.matched_subjects) == 1
    assert (
        report.subject_correlation.matched_subjects[0].extension_evidence["custom_subject_attr"]
        == "subject_ext_val"
    )

    # Check top-level predicate and statement extension preservation
    assert report.extension_evidence["custom_predicate_field"] == "pred_ext"
    assert report.extension_evidence["custom_statement_field"] == "stmt_ext"


def test_invalid_statement_type(valid_slsa_statement):
    valid_slsa_statement["_type"] = "https://in-toto.io/Statement/v0.1"
    validator = SLSAProvenanceValidator()
    with pytest.raises(ProvenanceValidationError) as exc:
        validator.validate_statement(valid_slsa_statement)
    assert "Invalid statement _type" in str(exc.value)


def test_invalid_predicate_type(valid_slsa_statement):
    valid_slsa_statement["predicateType"] = "https://slsa.dev/provenance/v0.2"
    validator = SLSAProvenanceValidator()
    with pytest.raises(ProvenanceValidationError) as exc:
        validator.validate_statement(valid_slsa_statement)
    assert "Invalid predicateType" in str(exc.value)


def test_subject_correlation_multiple_matches(valid_slsa_statement):
    target_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    valid_slsa_statement["subject"].append(
        {
            "name": "release-duplicate.tar.gz",
            "digest": {"sha256": target_sha},
        }
    )

    validator = SLSAProvenanceValidator()
    report = validator.validate_statement(valid_slsa_statement, target_artifact_sha256=target_sha)

    assert report.subject_correlation.matching_mode == "MULTIPLE_SUBJECTS_MATCH"
    assert report.subject_correlation.subject_digest_match is False
    assert report.subject_correlation.matching_subject_count == 2
    assert len(report.subject_correlation.matched_subjects) == 2


def test_subject_correlation_zero_matches(valid_slsa_statement):
    target_sha = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    validator = SLSAProvenanceValidator()
    report = validator.validate_statement(valid_slsa_statement, target_artifact_sha256=target_sha)

    assert report.subject_correlation.matching_mode == "ZERO_SUBJECT_MATCH"
    assert report.subject_correlation.subject_digest_match is False
    assert report.subject_correlation.matching_subject_count == 0
    assert len(report.subject_correlation.matched_subjects) == 0
    assert len(report.subject_correlation.all_subjects_observed) == 1


def test_resource_limit_subjects_count(valid_slsa_statement):
    valid_slsa_statement["subject"] = [
        {
            "name": f"item_{i}",
            "digest": {
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
        }
        for i in range(MAX_SUBJECTS_COUNT + 1)
    ]
    validator = SLSAProvenanceValidator()
    with pytest.raises(ProvenanceValidationError) as exc:
        validator.validate_statement(valid_slsa_statement)
    assert "Subject count" in str(exc.value) and "exceeds limit" in str(exc.value)


def test_resource_limit_resolved_dependencies_count(valid_slsa_statement):
    valid_slsa_statement["predicate"]["buildDefinition"]["resolvedDependencies"] = [
        {"uri": f"dep_{i}"} for i in range(MAX_RESOLVED_DEPENDENCIES_COUNT + 1)
    ]
    validator = SLSAProvenanceValidator()
    with pytest.raises(ProvenanceValidationError) as exc:
        validator.validate_statement(valid_slsa_statement)
    assert "resolvedDependencies count" in str(exc.value)


def test_resource_limit_byproducts_count(valid_slsa_statement):
    valid_slsa_statement["predicate"]["runDetails"]["byproducts"] = [
        {"name": f"bp_{i}"} for i in range(MAX_BYPRODUCTS_COUNT + 1)
    ]
    validator = SLSAProvenanceValidator()
    with pytest.raises(ProvenanceValidationError) as exc:
        validator.validate_statement(valid_slsa_statement)
    assert "byproducts count" in str(exc.value)


def test_resource_limit_json_nesting_depth():
    # Build deeply nested dictionary > 32 levels
    deep_dict = {"a": "b"}
    for _ in range(MAX_JSON_NESTING_DEPTH + 2):
        deep_dict = {"nested": deep_dict}

    validator = SLSAProvenanceValidator()
    with pytest.raises(ProvenanceValidationError) as exc:
        validator.validate_statement(deep_dict)
    assert "JSON nesting depth exceeds" in str(exc.value)
