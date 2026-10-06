"""
in-toto Statement v1 & SLSA v1.2 Provenance Validator.
"""

import json
from typing import Any, Dict, List, Optional, Union

from provenanceguard.core.verification.exceptions import ProvenanceValidationError
from provenanceguard.core.verification.provenance_models import (
    BuildDefinitionEvidence,
    JsonValue,
    RunDetailsEvidence,
    SLSAProvenanceReport,
    SubjectCorrelationDetails,
    SubjectEvidence,
)

# Resource limits
MAX_SUBJECTS_COUNT = 128
MAX_RESOLVED_DEPENDENCIES_COUNT = 1000
MAX_BYPRODUCTS_COUNT = 1000
MAX_JSON_NESTING_DEPTH = 32


def check_json_nesting_depth(data: Any, current_depth: int = 1) -> int:
    """Recursively determine JSON nesting depth."""
    if current_depth > MAX_JSON_NESTING_DEPTH:
        raise ProvenanceValidationError(
            f"JSON nesting depth exceeds maximum limit of {MAX_JSON_NESTING_DEPTH}"
        )
    if isinstance(data, dict):
        if not data:
            return current_depth
        return max(check_json_nesting_depth(v, current_depth + 1) for v in data.values())
    elif isinstance(data, list):
        if not data:
            return current_depth
        return max(check_json_nesting_depth(item, current_depth + 1) for item in data)
    return current_depth


def parse_json_value(val: Any) -> JsonValue:
    """Ensure arbitrary value conforms to recursive JsonValue type."""
    if val is None or isinstance(val, (bool, int, float, str)):
        return val
    elif isinstance(val, list):
        return [parse_json_value(item) for item in val]
    elif isinstance(val, dict):
        return {str(k): parse_json_value(v) for k, v in val.items()}
    else:
        return str(val)


class SLSAProvenanceValidator:
    """Validator for in-toto Statement v1 and SLSA v1.2 provenance statements."""

    def validate_statement(
        self,
        statement_data: Union[Dict[str, Any], str, bytes],
        target_artifact_sha256: Optional[str] = None,
    ) -> SLSAProvenanceReport:
        """
        Validate statement structure, parse open-ended parameters as JsonValue,
        preserve unknown extensions at location, and evaluate subject correlation.
        """
        warnings: List[str] = []

        if isinstance(statement_data, (str, bytes)):
            raw_bytes = (
                statement_data.encode("utf-8")
                if isinstance(statement_data, str)
                else statement_data
            )
            try:
                stmt_dict = json.loads(raw_bytes)
            except Exception as e:
                raise ProvenanceValidationError(f"Failed to parse statement JSON: {str(e)}") from e
        elif isinstance(statement_dict := statement_data, dict):
            stmt_dict = statement_dict
        else:
            raise ProvenanceValidationError("Invalid statement data type")

        if not isinstance(stmt_dict, dict):
            raise ProvenanceValidationError("Statement must be a JSON object")

        check_json_nesting_depth(stmt_dict)

        # Top-level in-toto Statement v1 validation
        stmt_type = stmt_dict.get("_type")
        predicate_type = stmt_dict.get("predicateType")
        subjects_raw = stmt_dict.get("subject")
        predicate_raw = stmt_dict.get("predicate")

        if stmt_type != "https://in-toto.io/Statement/v1":
            raise ProvenanceValidationError(
                "Invalid statement _type: expected "
                f"'https://in-toto.io/Statement/v1', got '{stmt_type}'"
            )

        if predicate_type != "https://slsa.dev/provenance/v1":
            raise ProvenanceValidationError(
                "Invalid predicateType: expected "
                f"'https://slsa.dev/provenance/v1', got '{predicate_type}'"
            )

        if not isinstance(subjects_raw, list):
            raise ProvenanceValidationError("Statement 'subject' must be a JSON array")

        if len(subjects_raw) > MAX_SUBJECTS_COUNT:
            raise ProvenanceValidationError(
                f"Subject count ({len(subjects_raw)}) exceeds limit ({MAX_SUBJECTS_COUNT})"
            )

        if not isinstance(predicate_raw, dict):
            raise ProvenanceValidationError("Statement 'predicate' must be a JSON object")

        # Subject Parsing & Location Extension Preservation
        all_subjects_observed: List[SubjectEvidence] = []
        known_subject_keys = {"name", "digest"}

        for idx, sub_raw in enumerate(subjects_raw):
            if not isinstance(sub_raw, dict):
                raise ProvenanceValidationError(f"Subject at index {idx} must be a JSON object")

            name = sub_raw.get("name")
            digest_dict = sub_raw.get("digest")

            if name is not None and not isinstance(name, str):
                raise ProvenanceValidationError(
                    f"Subject at index {idx} 'name' must be a string if provided"
                )

            if not isinstance(digest_dict, dict) or not digest_dict:
                raise ProvenanceValidationError(
                    f"Subject at index {idx} must contain a non-empty 'digest' dictionary"
                )

            # Preserve unknown subject fields
            subject_extensions: Dict[str, JsonValue] = {
                k: parse_json_value(v) for k, v in sub_raw.items() if k not in known_subject_keys
            }

            for alg, dig_val in digest_dict.items():
                if not isinstance(dig_val, str):
                    raise ProvenanceValidationError(
                        f"Subject digest value for algorithm '{alg}' at index {idx} "
                        "must be a string"
                    )
                all_subjects_observed.append(
                    SubjectEvidence(
                        name=name,
                        digest_algorithm=str(alg).lower(),
                        digest=str(dig_val).lower(),
                        extension_evidence=subject_extensions,
                    )
                )

        # Subject Correlation
        matching_indices: List[int] = []
        matched_subjects: List[SubjectEvidence] = []

        if target_artifact_sha256:
            target_clean = target_artifact_sha256.lower()
            for idx, sub in enumerate(all_subjects_observed):
                if sub.digest_algorithm == "sha256" and sub.digest == target_clean:
                    matching_indices.append(idx)
                    matched_subjects.append(sub)

            matching_count = len(matched_subjects)
            if matching_count == 1:
                matching_mode = "EXACT_ONE_MATCH"
                subject_digest_match = True
            elif matching_count > 1:
                matching_mode = "MULTIPLE_SUBJECTS_MATCH"
                subject_digest_match = False
                warnings.append(
                    f"Multiple subjects ({matching_count}) matched target artifact SHA-256"
                )
            else:
                matching_mode = "ZERO_SUBJECT_MATCH"
                subject_digest_match = False
                warnings.append(f"Zero subjects matched target artifact SHA-256 ({target_clean})")
        else:
            matching_mode = "NOT_EVALUATED"
            matching_count = 0
            subject_digest_match = False

        subject_correlation = SubjectCorrelationDetails(
            target_artifact_sha256=target_artifact_sha256 or "",
            matching_mode=matching_mode,
            matching_subject_count=matching_count,
            matching_subject_indices=matching_indices,
            matched_subjects=matched_subjects,
            subject_digest_match=subject_digest_match,
            all_subjects_observed=all_subjects_observed,
        )

        # SLSA buildDefinition Parsing
        build_def_raw = predicate_raw.get("buildDefinition")
        if not isinstance(build_def_raw, dict):
            raise ProvenanceValidationError(
                "Predicate missing required dictionary 'buildDefinition'"
            )

        build_type = build_def_raw.get("buildType")
        if not isinstance(build_type, str):
            raise ProvenanceValidationError("buildDefinition missing required string 'buildType'")

        external_params_raw = build_def_raw.get("externalParameters", {})
        internal_params_raw = build_def_raw.get("internalParameters", {})
        resolved_deps_raw = build_def_raw.get("resolvedDependencies", [])

        if not isinstance(external_params_raw, dict):
            raise ProvenanceValidationError(
                "buildDefinition 'externalParameters' must be a JSON object"
            )

        if not isinstance(internal_params_raw, dict):
            raise ProvenanceValidationError(
                "buildDefinition 'internalParameters' must be a JSON object"
            )

        if not isinstance(resolved_deps_raw, list):
            raise ProvenanceValidationError(
                "buildDefinition 'resolvedDependencies' must be a JSON array"
            )

        if len(resolved_deps_raw) > MAX_RESOLVED_DEPENDENCIES_COUNT:
            raise ProvenanceValidationError(
                f"resolvedDependencies count ({len(resolved_deps_raw)}) "
                f"exceeds limit ({MAX_RESOLVED_DEPENDENCIES_COUNT})"
            )

        known_build_def_keys = {
            "buildType",
            "externalParameters",
            "internalParameters",
            "resolvedDependencies",
        }
        build_def_extensions: Dict[str, JsonValue] = {
            k: parse_json_value(v)
            for k, v in build_def_raw.items()
            if k not in known_build_def_keys
        }

        build_definition = BuildDefinitionEvidence(
            build_type=build_type,
            external_parameters={k: parse_json_value(v) for k, v in external_params_raw.items()},
            internal_parameters={k: parse_json_value(v) for k, v in internal_params_raw.items()},
            resolved_dependencies=[parse_json_value(dep) for dep in resolved_deps_raw],  # type: ignore
            extension_evidence=build_def_extensions,
        )

        # SLSA runDetails Parsing
        run_details_raw = predicate_raw.get("runDetails")
        if not isinstance(run_details_raw, dict):
            raise ProvenanceValidationError("Predicate missing required dictionary 'runDetails'")

        builder_raw = run_details_raw.get("builder", {})
        if not isinstance(builder_raw, dict):
            raise ProvenanceValidationError("runDetails 'builder' must be a JSON object")

        builder_id = builder_raw.get("id")
        if builder_id is not None and not isinstance(builder_id, str):
            raise ProvenanceValidationError("builder 'id' must be a string if provided")

        builder_metadata_raw = run_details_raw.get("metadata", {})
        byproducts_raw = run_details_raw.get("byproducts", [])

        if not isinstance(builder_metadata_raw, dict):
            raise ProvenanceValidationError("runDetails 'metadata' must be a JSON object")

        if not isinstance(byproducts_raw, list):
            raise ProvenanceValidationError("runDetails 'byproducts' must be a JSON array")

        if len(byproducts_raw) > MAX_BYPRODUCTS_COUNT:
            raise ProvenanceValidationError(
                f"byproducts count ({len(byproducts_raw)}) exceeds limit ({MAX_BYPRODUCTS_COUNT})"
            )

        known_run_details_keys = {"builder", "metadata", "byproducts"}
        run_details_extensions: Dict[str, JsonValue] = {
            k: parse_json_value(v)
            for k, v in run_details_raw.items()
            if k not in known_run_details_keys
        }

        run_details = RunDetailsEvidence(
            builder_id=builder_id,
            builder_metadata={k: parse_json_value(v) for k, v in builder_metadata_raw.items()},
            byproducts=[parse_json_value(bp) for bp in byproducts_raw],  # type: ignore
            extension_evidence=run_details_extensions,
        )

        # Top-level predicate extensions
        known_predicate_keys = {"buildDefinition", "runDetails"}
        predicate_extensions: Dict[str, JsonValue] = {
            k: parse_json_value(v)
            for k, v in predicate_raw.items()
            if k not in known_predicate_keys
        }

        # Top-level statement extensions
        known_stmt_keys = {"_type", "predicateType", "subject", "predicate"}
        statement_extensions: Dict[str, JsonValue] = {
            k: parse_json_value(v) for k, v in stmt_dict.items() if k not in known_stmt_keys
        }

        # Combine predicate and statement extensions into report extension_evidence
        all_top_extensions = {**predicate_extensions, **statement_extensions}

        return SLSAProvenanceReport(
            statement_version=stmt_type,
            predicate_type=predicate_type,
            build_definition=build_definition,
            run_details=run_details,
            subject_correlation=subject_correlation,
            extension_evidence=all_top_extensions,
            warnings=warnings,
        )
