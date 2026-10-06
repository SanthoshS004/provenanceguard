"""
Unit Tests for Isolated Reference Builder Module
"""

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from provenanceguard.builders.isolated.artifact_collector import (
    collect_build_artifacts,
)
from provenanceguard.builders.isolated.exceptions import (
    ArtifactCollectionError,
    ImageResolutionError,
    SCMValidationError,
    SpecialFileViolationError,
)
from provenanceguard.builders.isolated.image_verifier import (
    parse_and_validate_image_reference,
    verify_image_manifest_digest,
)
from provenanceguard.builders.isolated.models import (
    BuildConfig,
    SCMMetadata,
    ToolchainSpec,
)
from provenanceguard.builders.isolated.scm_validator import validate_scm_url
from provenanceguard.core.domain.exceptions import DomainValidationError

VALID_SHA256 = "a" * 64
VALID_COMMIT = "b" * 40


def test_scm_url_validation_success():
    meta = validate_scm_url("https://github.com/org/repo.git", VALID_COMMIT)
    assert meta.scm_url == "https://github.com/org/repo.git"
    assert meta.commit_sha == VALID_COMMIT


def test_scm_url_validation_rejects_credentials():
    with pytest.raises(SCMValidationError, match="embedded user credentials"):
        validate_scm_url("https://user:password@github.com/org/repo.git", VALID_COMMIT)


def test_scm_url_validation_rejects_token():
    with pytest.raises(SCMValidationError, match="embedded user credentials"):
        validate_scm_url(
            "https://x-access-token:ghp_123456789@github.com/org/repo.git", VALID_COMMIT
        )


def test_image_reference_parser_success():
    parsed = parse_and_validate_image_reference(
        f"localhost:5000/myrepo/builder:v1.0@sha256:{VALID_SHA256}"
    )
    assert parsed.repository == "localhost:5000/myrepo/builder"
    assert parsed.tag == "v1.0"
    assert parsed.digest == VALID_SHA256


def test_image_reference_parser_rejects_tag_only():
    with pytest.raises(ImageResolutionError, match="missing mandatory '@sha256:' digest"):
        parse_and_validate_image_reference("gcc:12")


def test_image_reference_parser_rejects_latest():
    with pytest.raises(ImageResolutionError, match="missing mandatory '@sha256:' digest"):
        parse_and_validate_image_reference("builder:latest")


def test_image_reference_manifest_digest_verifier():
    mock_client = MagicMock()
    repo_digests = [f"localhost:5000/builder@sha256:{VALID_SHA256}"]
    assert verify_image_manifest_digest(mock_client, VALID_SHA256, repo_digests) is True
    assert verify_image_manifest_digest(mock_client, "c" * 64, repo_digests) is False


def test_build_config_command_validation_exec_form():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)

    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make", "build"],
    )
    assert config.build_command == ["make", "build"]

    with pytest.raises(DomainValidationError):
        BuildConfig(
            src_dir=Path("/tmp/src"),
            out_dir=Path("/tmp/out"),
            toolchain=toolchain,
            scm=scm,
            build_command=[],
        )


def test_toolchain_spec_prohibited_secret_keys():
    with pytest.raises(DomainValidationError, match="Prohibited secret"):
        ToolchainSpec(
            image_ref=f"builder@sha256:{VALID_SHA256}",
            digest=VALID_SHA256,
            environment={"AWS_SECRET_ACCESS_KEY": "supersecret"},
        )


def test_artifact_collector_stopped_container_assertion(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"

    with pytest.raises(ArtifactCollectionError, match="requested while container is running"):
        collect_build_artifacts(out_dir, dest_dir, container_is_running=True)


def test_artifact_collector_regular_file_hardlink_rejection(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"

    file1 = out_dir / "file1.txt"
    file1.write_text("hello")

    file2 = out_dir / "file2.txt"
    try:
        os.link(file1, file2)
    except OSError:
        pytest.skip("Hardlinks not supported on host OS filesystem")

    with pytest.raises(SpecialFileViolationError, match="hardlink count"):
        collect_build_artifacts(out_dir, dest_dir, container_is_running=False)


def test_artifact_collector_directory_link_count_accepted(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sub_dir = out_dir / "subdir"
    sub_dir.mkdir()

    file1 = sub_dir / "artifact.bin"
    file1.write_bytes(b"data")

    dest_dir = tmp_path / "dest"
    collected = collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    assert len(collected) == 1
    assert collected[0].name == "artifact.bin"
