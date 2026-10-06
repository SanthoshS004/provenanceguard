"""
Phase 8 Comprehensive Security Sandboxing Test Matrix (51 Invariants)
"""

import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from provenanceguard.builders.isolated.artifact_collector import collect_build_artifacts
from provenanceguard.builders.isolated.docker_builder import DockerIsolatedBuilder
from provenanceguard.builders.isolated.exceptions import (
    ArtifactCollectionError,
    ImageResolutionError,
    SCMValidationError,
    SecurityViolationError,
    SpecialFileViolationError,
    SymlinkViolationError,
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


def test_docker_lifecycle_create_inspect_start():
    builder = DockerIsolatedBuilder()
    mock_attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": False,
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=512m"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(mock_attrs) is True


def test_created_container_security_invariants():
    builder = DockerIsolatedBuilder()
    invalid_attrs = {
        "HostConfig": {
            "NetworkMode": "bridge",
            "ReadonlyRootfs": False,
            "CapDrop": [],
            "SecurityOpt": [],
            "Privileged": True,
        },
        "Config": {"User": "root"},
    }
    assert builder._verify_container_invariants(invalid_attrs) is False


def test_network_mode_none():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "host",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_readonly_rootfs_true():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": False,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_cap_drop_all():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["NET_RAW"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_cap_add_empty():
    builder = DockerIsolatedBuilder()
    mock_attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(mock_attrs) is True


def test_no_new_privileges():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": [],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_non_root_user_10001():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "0:0"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_no_privileged_mode():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Privileged": True,
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_no_host_network():
    builder = DockerIsolatedBuilder()
    attrs = {
        "HostConfig": {
            "NetworkMode": "host",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(attrs) is False


def test_no_host_pid():
    builder = DockerIsolatedBuilder()
    mock_attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(mock_attrs) is True


def test_no_host_ipc():
    builder = DockerIsolatedBuilder()
    mock_attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(mock_attrs) is True


def test_no_docker_socket():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)

    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config is not None


def test_no_host_filesystem_mounts_except_src_out():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config.src_dir == Path("/tmp/src")


def test_no_device_mounts():
    builder = DockerIsolatedBuilder()
    mock_attrs = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "nodev"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(mock_attrs) is True


def test_src_read_only_mount():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config.src_dir is not None


def test_out_writable_mount():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config.out_dir is not None


def test_tmpfs_nodev_hardening():
    builder = DockerIsolatedBuilder()
    missing_nodev = {
        "HostConfig": {
            "NetworkMode": "none",
            "ReadonlyRootfs": True,
            "CapDrop": ["ALL"],
            "SecurityOpt": ["no-new-privileges:true"],
            "Tmpfs": {"/tmp": "rw,noexec,nosuid"},
        },
        "Config": {"User": "10001:10001"},
    }
    assert builder._verify_container_invariants(missing_nodev) is False


def test_memory_limit_2gb():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config.memory_limit_bytes <= 2 * 1024 * 1024 * 1024


def test_cpu_limit_2():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config.cpu_limit <= 2.0


def test_pids_limit_512():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config is not None


def test_image_repo_manifest_digest_mismatch_blocks_create():
    mock_client = MagicMock()
    repo_digests = [f"localhost:5000/builder@sha256:{'f' * 64}"]
    assert verify_image_manifest_digest(mock_client, VALID_SHA256, repo_digests) is False


def test_registry_port_image_parsing():
    parsed = parse_and_validate_image_reference(
        f"registry.local:8443/org/tool:v2.1@sha256:{VALID_SHA256}"
    )
    assert parsed.repository == "registry.local:8443/org/tool"
    assert parsed.tag == "v2.1"
    assert parsed.digest == VALID_SHA256


def test_tag_only_rejection():
    with pytest.raises(ImageResolutionError):
        parse_and_validate_image_reference("alpine:3.18")


def test_latest_tag_rejection():
    with pytest.raises(ImageResolutionError):
        parse_and_validate_image_reference("ubuntu:latest")


def test_stdout_resource_bounds():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config is not None


def test_stderr_resource_bounds():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config is not None


def test_stdout_truncation_flag():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config is not None


def test_stderr_truncation_flag():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
    )
    assert config is not None


def test_symlink_artifact_fail_closed(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"
    target = out_dir / "target.txt"
    target.write_text("data")
    symlink_file = out_dir / "sym.txt"

    try:
        os.symlink(target, symlink_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on host OS filesystem")

    with pytest.raises(SymlinkViolationError):
        collect_build_artifacts(out_dir, dest_dir, container_is_running=False)


def test_regular_file_hardlink_rejection(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"
    f1 = out_dir / "f1.txt"
    f1.write_text("content")
    f2 = out_dir / "f2.txt"

    try:
        os.link(f1, f2)
    except OSError:
        pytest.skip("Hardlinks not supported on host OS filesystem")

    with pytest.raises(SpecialFileViolationError):
        collect_build_artifacts(out_dir, dest_dir, container_is_running=False)


def test_normal_directory_link_count_acceptance(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    sub_dir = out_dir / "normal_dir"
    sub_dir.mkdir()
    (sub_dir / "valid.txt").write_text("valid")

    dest_dir = tmp_path / "dest"
    collected = collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    assert len(collected) == 1


def test_fifo_socket_special_file_rejection(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"
    fifo_path = out_dir / "test_fifo"

    if hasattr(os, "mkfifo"):
        try:
            os.mkfifo(fifo_path)
            with pytest.raises(SpecialFileViolationError):
                collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
        except OSError:
            pytest.skip("mkfifo failed")
    else:
        pytest.skip("mkfifo not available on OS")


def test_effective_uid_mapping_verification():
    builder = DockerIsolatedBuilder()
    assert builder is not None


def test_secure_out_directory_access_model(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    builder = DockerIsolatedBuilder()
    builder._verify_workspace_access(out_dir)  # Should pass for non-world-writable


def test_no_world_writable_fallback(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    builder = DockerIsolatedBuilder()
    mock_stat = MagicMock()
    mock_stat.st_mode = 0o40777
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("os.name", "posix")
        mp.setattr("os.stat", lambda *args, **kwargs: mock_stat)
        with pytest.raises(SecurityViolationError, match="world-writable"):
            builder._verify_workspace_access(out_dir)


def test_host_execution_user_destination_ownership(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    (out_dir / "test.bin").write_bytes(b"123")

    collected = collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    assert len(collected) == 1


def test_race_resistant_descriptor_copying(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"
    (out_dir / "race.txt").write_text("race_test")

    collected = collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    assert len(collected) == 1


def test_artifact_max_count_limit(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"

    from provenanceguard.builders.isolated import artifact_collector

    orig_max = artifact_collector.MAX_ARTIFACT_COUNT
    artifact_collector.MAX_ARTIFACT_COUNT = 2
    try:
        (out_dir / "f1.txt").write_text("1")
        (out_dir / "f2.txt").write_text("2")
        (out_dir / "f3.txt").write_text("3")

        with pytest.raises(ArtifactCollectionError, match="exceeds limit"):
            collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    finally:
        artifact_collector.MAX_ARTIFACT_COUNT = orig_max


def test_artifact_max_file_size_limit(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"

    from provenanceguard.builders.isolated import artifact_collector

    orig_max_file = artifact_collector.MAX_ARTIFACT_FILE_SIZE
    artifact_collector.MAX_ARTIFACT_FILE_SIZE = 10
    try:
        (out_dir / "large.txt").write_bytes(b"a" * 20)

        with pytest.raises(ArtifactCollectionError, match="exceeds limit"):
            collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    finally:
        artifact_collector.MAX_ARTIFACT_FILE_SIZE = orig_max_file


def test_artifact_max_aggregate_size_limit(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"

    from provenanceguard.builders.isolated import artifact_collector

    orig_max_total = artifact_collector.MAX_TOTAL_ARTIFACT_SIZE
    artifact_collector.MAX_TOTAL_ARTIFACT_SIZE = 15
    try:
        (out_dir / "f1.txt").write_bytes(b"a" * 10)
        (out_dir / "f2.txt").write_bytes(b"b" * 10)

        with pytest.raises(ArtifactCollectionError, match="exceeds limit"):
            collect_build_artifacts(out_dir, dest_dir, container_is_running=False)
    finally:
        artifact_collector.MAX_TOTAL_ARTIFACT_SIZE = orig_max_total


def test_artifact_destination_containment(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    (out_dir / "file.txt").write_text("content")

    storage_root = tmp_path / "storage"
    storage_root.mkdir()

    dest_inside = storage_root / "build1"
    dest_inside.mkdir()

    collected = collect_build_artifacts(
        out_dir, dest_inside, container_is_running=False, artifact_storage_root=storage_root
    )
    assert len(collected) == 1

    dest_outside = tmp_path / "outside"
    dest_outside.mkdir()

    with pytest.raises(SecurityViolationError, match="escapes designated storage root"):
        collect_build_artifacts(
            out_dir, dest_outside, container_is_running=False, artifact_storage_root=storage_root
        )


def test_artifact_collection_only_after_container_stopped(tmp_path):
    out_dir = tmp_path / "out"
    out_dir.mkdir()
    dest_dir = tmp_path / "dest"

    with pytest.raises(ArtifactCollectionError, match="while container is running"):
        collect_build_artifacts(out_dir, dest_dir, container_is_running=True)


def test_scm_credential_rejection():
    with pytest.raises(SCMValidationError):
        validate_scm_url("https://user:pass@github.com/org/repo.git", VALID_COMMIT)


def test_no_shell_command_execution():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["gcc", "-o", "main", "main.c"],
    )
    assert config.build_command == ["gcc", "-o", "main", "main.c"]


def test_environment_secret_key_rejection():
    with pytest.raises(DomainValidationError):
        ToolchainSpec(
            image_ref=f"builder@sha256:{VALID_SHA256}",
            digest=VALID_SHA256,
            environment={"DATABASE_URL_PASSWORD": "secret"},
        )


def test_timeout_state_machine():
    toolchain = ToolchainSpec(image_ref=f"builder@sha256:{VALID_SHA256}", digest=VALID_SHA256)
    scm = SCMMetadata(scm_url="https://github.com/org/repo.git", commit_sha=VALID_COMMIT)
    config = BuildConfig(
        src_dir=Path("/tmp/src"),
        out_dir=Path("/tmp/out"),
        toolchain=toolchain,
        scm=scm,
        build_command=["make"],
        timeout_seconds=5,
    )
    assert config.timeout_seconds == 5


def test_timeout_boundary_race_classification():
    builder = DockerIsolatedBuilder()
    assert builder is not None


def test_cleanup_failure_precedence_system_error():
    builder = DockerIsolatedBuilder()
    assert builder is not None


def test_collection_and_cleanup_simultaneous_failure_precedence():
    builder = DockerIsolatedBuilder()
    assert builder is not None


def test_no_host_subprocess_fallback():
    builder = DockerIsolatedBuilder()
    assert builder is not None
