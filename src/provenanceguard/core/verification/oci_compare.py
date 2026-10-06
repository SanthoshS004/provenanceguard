"""
OCI Container Image Structural RootFS & Config Comparison Engine.
Compares Production OCI RootFS vs Trusted Reference OCI RootFS (Phase 8 Builder).
"""

import re
from typing import Any, Dict, List

from pydantic import BaseModel, Field

from provenanceguard.analyzers.oci.oci_adapters import OCIMalformedConfigError
from provenanceguard.analyzers.oci.oci_extraction import VirtualRootFS
from provenanceguard.analyzers.oci.oci_spec import NormalizedOCIImage
from provenanceguard.core.verification.models import (
    ComparisonResult,
    DependencyDelta,
    FunctionDelta,
    FunctionInventoryCompleteness,
    SecurityObservationDelta,
    StructuralDelta,
)

SECRET_KEY_PATTERN = re.compile(
    r"(password|secret|token|api_key|access_key|private_key|auth)", re.IGNORECASE
)


def normalize_env_dict(env_list: List[str]) -> Dict[str, str]:
    """
    Parses OCI Config.Env array of "KEY=VALUE" strings.
    Duplicate keys are canonicalized using deterministic last-occurrence-wins semantics.
    Rejects malformed entries without '='.
    """
    env_dict: Dict[str, str] = {}
    for entry in env_list:
        if "=" not in entry:
            raise OCIMalformedConfigError(f"Malformed Env string missing '=': '{entry}'")
        key, val = entry.split("=", 1)
        key_clean = key.strip()
        env_dict[key_clean] = val

    return env_dict


def redact_secret_env_value(key: str, val: str) -> str:
    """Masks secret environment variable values in audit findings."""
    if SECRET_KEY_PATTERN.search(key):
        return "***REDACTED***"
    return val


class OCIComparisonResult(BaseModel):
    """
    Deterministic evidence payload for OCI Image comparison.
    Contains strictly objective diff evidence; zero policy verdicts or risk scores.
    """

    reference_manifest_digest: str
    production_manifest_digest: str
    manifest_digest_matches: bool
    config_diffs: List[Dict[str, Any]] = Field(default_factory=list)
    non_elf_file_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    symlink_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    directory_deltas: List[Dict[str, Any]] = Field(default_factory=list)
    comparison_result: ComparisonResult


class OCIImageComparer:
    """
    Compares Production OCI Image vs Trusted Reference OCI Image.
    """

    def compare_images(
        self,
        reference_image: NormalizedOCIImage,
        production_image: NormalizedOCIImage,
        ref_virtual_fs: VirtualRootFS,
        prod_virtual_fs: VirtualRootFS,
    ) -> OCIComparisonResult:
        """
        Executes structural RootFS and Image Config comparison.
        """
        ref_digest = reference_image.selected_manifest_digest
        prod_digest = production_image.selected_manifest_digest
        digest_matches = ref_digest.lower() == prod_digest.lower()

        # 1. Image Config Comparison (Env, Entrypoint, Cmd, User, WorkingDir)
        config_diffs = self._compare_image_configs(
            reference_image.config.config, production_image.config.config
        )

        # 2. Structural RootFS Diffs
        structural_deltas: List[StructuralDelta] = []
        function_deltas: List[FunctionDelta] = []
        dependency_deltas: List[DependencyDelta] = []
        security_observation_deltas: List[SecurityObservationDelta] = []
        non_elf_file_deltas: List[Dict[str, Any]] = []
        symlink_deltas: List[Dict[str, Any]] = []
        directory_deltas: List[Dict[str, Any]] = []

        # A. Non-ELF Regular File Diffs
        ref_files = ref_virtual_fs.files
        prod_files = prod_virtual_fs.files

        all_file_paths = sorted(list(set(ref_files.keys()) | set(prod_files.keys())))
        for path in all_file_paths:
            if path in ref_files and path not in prod_files:
                non_elf_file_deltas.append(
                    {
                        "delta_type": "FILE_REMOVED",
                        "path": path,
                        "old_sha256": ref_files[path].sha256,
                        "new_sha256": None,
                    }
                )
            elif path not in ref_files and path in prod_files:
                non_elf_file_deltas.append(
                    {
                        "delta_type": "FILE_ADDED",
                        "path": path,
                        "old_sha256": None,
                        "new_sha256": prod_files[path].sha256,
                    }
                )
            else:
                r_file = ref_files[path]
                p_file = prod_files[path]
                if r_file.sha256 != p_file.sha256:
                    non_elf_file_deltas.append(
                        {
                            "delta_type": "FILE_CONTENT_CHANGED",
                            "path": path,
                            "old_sha256": r_file.sha256,
                            "new_sha256": p_file.sha256,
                        }
                    )

        # B. Inert Symlink Target Diffs (NEVER dereferenced or followed)
        ref_symlinks = ref_virtual_fs.symlinks
        prod_symlinks = prod_virtual_fs.symlinks

        all_symlink_paths = sorted(list(set(ref_symlinks.keys()) | set(prod_symlinks.keys())))
        for path in all_symlink_paths:
            if path in ref_symlinks and path not in prod_symlinks:
                symlink_deltas.append(
                    {
                        "delta_type": "SYMLINK_REMOVED",
                        "path": path,
                        "old_target": ref_symlinks[path].target,
                        "new_target": None,
                    }
                )
            elif path not in ref_symlinks and path in prod_symlinks:
                symlink_deltas.append(
                    {
                        "delta_type": "SYMLINK_ADDED",
                        "path": path,
                        "old_target": None,
                        "new_target": prod_symlinks[path].target,
                    }
                )
            else:
                r_sym = ref_symlinks[path]
                p_sym = prod_symlinks[path]
                if r_sym.target != p_sym.target:
                    symlink_deltas.append(
                        {
                            "delta_type": "SYMLINK_TARGET_CHANGED",
                            "path": path,
                            "old_target": r_sym.target,
                            "new_target": p_sym.target,
                        }
                    )

        # C. Directory Diffs
        ref_dirs = ref_virtual_fs.directories
        prod_dirs = prod_virtual_fs.directories
        all_dir_paths = sorted(list(set(ref_dirs.keys()) | set(prod_dirs.keys())))
        for path in all_dir_paths:
            if path in ref_dirs and path not in prod_dirs:
                directory_deltas.append({"delta_type": "DIRECTORY_REMOVED", "path": path})
            elif path not in ref_dirs and path in prod_dirs:
                directory_deltas.append({"delta_type": "DIRECTORY_ADDED", "path": path})

        base_comparison_result = ComparisonResult(
            reference_artifact_digest=ref_digest,
            target_artifact_digest=prod_digest,
            digest_matches=digest_matches,
            reference_completeness=FunctionInventoryCompleteness.COMPLETE,
            target_completeness=FunctionInventoryCompleteness.COMPLETE,
            is_partial_comparison=False,
            structural_deltas=structural_deltas,
            function_deltas=function_deltas,
            dependency_deltas=dependency_deltas,
            security_observation_deltas=security_observation_deltas,
        )
        base_comparison_result.sort_deltas()

        return OCIComparisonResult(
            reference_manifest_digest=ref_digest,
            production_manifest_digest=prod_digest,
            manifest_digest_matches=digest_matches,
            config_diffs=config_diffs,
            non_elf_file_deltas=non_elf_file_deltas,
            symlink_deltas=symlink_deltas,
            directory_deltas=directory_deltas,
            comparison_result=base_comparison_result,
        )

    def _compare_image_configs(
        self,
        ref_config_dict: Dict[str, Any],
        prod_config_dict: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Compares Image Config fields (Env, Entrypoint, Cmd, User, WorkingDir)."""
        diffs: List[Dict[str, Any]] = []

        # 1. Env comparison (Order-only shifts ignored, last-occurrence-wins canonicalized)
        ref_env_list = ref_config_dict.get("Env", [])
        prod_env_list = prod_config_dict.get("Env", [])

        ref_env_dict = normalize_env_dict(ref_env_list) if isinstance(ref_env_list, list) else {}
        prod_env_dict = normalize_env_dict(prod_env_list) if isinstance(prod_env_list, list) else {}

        all_keys = sorted(list(set(ref_env_dict.keys()) | set(prod_env_dict.keys())))
        for k in all_keys:
            if k in ref_env_dict and k not in prod_env_dict:
                diffs.append(
                    {
                        "field": f"Env.{k}",
                        "delta_type": "ENV_KEY_REMOVED",
                        "old_value": redact_secret_env_value(k, ref_env_dict[k]),
                        "new_value": None,
                    }
                )
            elif k not in ref_env_dict and k in prod_env_dict:
                diffs.append(
                    {
                        "field": f"Env.{k}",
                        "delta_type": "ENV_KEY_ADDED",
                        "old_value": None,
                        "new_value": redact_secret_env_value(k, prod_env_dict[k]),
                    }
                )
            else:
                ref_val = ref_env_dict[k]
                prod_val = prod_env_dict[k]
                if ref_val != prod_val:
                    diffs.append(
                        {
                            "field": f"Env.{k}",
                            "delta_type": "ENV_VALUE_CHANGED",
                            "old_value": redact_secret_env_value(k, ref_val),
                            "new_value": redact_secret_env_value(k, prod_val),
                        }
                    )

        # 2. Entrypoint comparison (Order IS preserved)
        ref_entry = ref_config_dict.get("Entrypoint")
        prod_entry = prod_config_dict.get("Entrypoint")
        if ref_entry != prod_entry:
            diffs.append(
                {
                    "field": "Entrypoint",
                    "delta_type": "ENTRYPOINT_CHANGED",
                    "old_value": ref_entry,
                    "new_value": prod_entry,
                }
            )

        # 3. Cmd comparison (Order IS preserved)
        ref_cmd = ref_config_dict.get("Cmd")
        prod_cmd = prod_config_dict.get("Cmd")
        if ref_cmd != prod_cmd:
            diffs.append(
                {
                    "field": "Cmd",
                    "delta_type": "CMD_CHANGED",
                    "old_value": ref_cmd,
                    "new_value": prod_cmd,
                }
            )

        # 4. User comparison
        ref_user = ref_config_dict.get("User", "")
        prod_user = prod_config_dict.get("User", "")
        if ref_user != prod_user:
            diffs.append(
                {
                    "field": "User",
                    "delta_type": "USER_CHANGED",
                    "old_value": ref_user,
                    "new_value": prod_user,
                }
            )

        # 5. WorkingDir comparison
        ref_workdir = ref_config_dict.get("WorkingDir", "")
        prod_workdir = prod_config_dict.get("WorkingDir", "")
        if ref_workdir != prod_workdir:
            diffs.append(
                {
                    "field": "WorkingDir",
                    "delta_type": "WORKINGDIR_CHANGED",
                    "old_value": ref_workdir,
                    "new_value": prod_workdir,
                }
            )

        return diffs
