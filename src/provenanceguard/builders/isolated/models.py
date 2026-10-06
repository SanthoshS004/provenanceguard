"""
Domain Models and Value Objects for Isolated Builder Engine
"""

from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from provenanceguard.core.domain.exceptions import DomainValidationError
from provenanceguard.core.domain.value_objects import EnvironmentVariable


class IsolationStatus(str, Enum):
    """Execution status enum for reference build isolation."""

    SUCCESS = "SUCCESS"
    BUILD_FAILED = "BUILD_FAILED"
    TIMEOUT = "TIMEOUT"
    ISOLATION_VIOLATION = "ISOLATION_VIOLATION"
    IMAGE_RESOLUTION_ERROR = "IMAGE_RESOLUTION_ERROR"
    ARTIFACT_COLLECTION_ERROR = "ARTIFACT_COLLECTION_ERROR"
    SYSTEM_ERROR = "SYSTEM_ERROR"


class ToolchainSpec(BaseModel):
    """Toolchain specification including image reference and environment variables."""

    model_config = ConfigDict(frozen=True)

    image_ref: str = Field(..., description="Immutable image reference string")
    digest: str = Field(..., description="64-character SHA256 content digest")
    environment: Dict[str, str] = Field(
        default_factory=dict, description="Environment variables dictionary"
    )

    @field_validator("environment")
    @classmethod
    def validate_environment_keys(cls, env: Dict[str, str]) -> Dict[str, str]:
        """Verify no prohibited secret keys are submitted in build environment."""
        for key in env.keys():
            key_upper = key.strip().upper()
            if not key_upper:
                raise DomainValidationError("Environment variable key cannot be empty")
            for pattern in EnvironmentVariable.PROHIBITED_SECRET_PATTERNS:
                if pattern in key_upper:
                    raise DomainValidationError(
                        f"Prohibited secret environment variable key '{key}' "
                        "cannot be submitted in build environment",
                        field_name="environment",
                    )
        return env


class SCMMetadata(BaseModel):
    """Metadata for source revision tracking."""

    model_config = ConfigDict(frozen=True)

    scm_url: str = Field(..., description="Validated SCM repository URL string")
    commit_sha: str = Field(..., description="40-character commit SHA hex string")
    branch: Optional[str] = Field(default=None, description="Optional SCM branch name")
    tag: Optional[str] = Field(default=None, description="Optional SCM release tag name")

    @field_validator("commit_sha")
    @classmethod
    def validate_commit_sha(cls, v: str) -> str:
        v_clean = v.strip().lower()
        if len(v_clean) != 40 or not all(c in "0123456789abcdef" for c in v_clean):
            raise DomainValidationError(
                "Commit SHA must be a 40-character hexadecimal string", field_name="commit_sha"
            )
        return v_clean


class BuildConfig(BaseModel):
    """Configuration specification for isolated reference build execution."""

    model_config = ConfigDict(frozen=True)

    src_dir: Path = Field(..., description="Host source directory path")
    out_dir: Path = Field(..., description="Host output workspace directory path")
    toolchain: ToolchainSpec = Field(..., description="Toolchain image and environment spec")
    scm: SCMMetadata = Field(..., description="SCM metadata")
    build_command: List[str] = Field(
        ..., description="Exec-form build command arguments list (argv)"
    )
    timeout_seconds: int = Field(default=300, ge=1, le=3600, description="Build timeout limit")
    memory_limit_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024, le=2 * 1024 * 1024 * 1024, description="RAM limit in bytes"
    )
    cpu_limit: float = Field(default=2.0, le=2.0, description="CPU allocation limit")

    @field_validator("build_command")
    @classmethod
    def validate_build_command(cls, cmd: List[str]) -> List[str]:
        if not isinstance(cmd, list) or not cmd:
            raise DomainValidationError("build_command must be a non-empty list of strings")
        for arg in cmd:
            if not isinstance(arg, str) or not arg.strip():
                raise DomainValidationError("build_command arguments must be non-empty strings")
        return cmd


class BuildResult(BaseModel):
    """Result data object returned after reference build execution."""

    model_config = ConfigDict(frozen=True)

    status: IsolationStatus
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    artifact_paths: List[Path] = Field(default_factory=list)
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
