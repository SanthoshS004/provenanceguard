"""
Core Docker Isolated Builder Driver Implementation
"""

import os
import time
from pathlib import Path
from typing import Optional

from provenanceguard.builders.isolated.artifact_collector import collect_build_artifacts
from provenanceguard.builders.isolated.exceptions import (
    ArtifactCollectionError,
    BuilderError,
    ImageResolutionError,
    IsolationViolationError,
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
    BuildResult,
    IsolationStatus,
)
from provenanceguard.builders.isolated.scm_validator import validate_scm_url

MAX_STDOUT_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_STDERR_SIZE = 10 * 1024 * 1024  # 10 MB


class DockerIsolatedBuilder:
    """
    Unprivileged isolated reference builder driver using Docker engine daemon interface.
    No host subprocess execution fallbacks.
    """

    def __init__(self, docker_client=None):
        self._docker_client = docker_client

    def _get_client(self):
        if self._docker_client is not None:
            return self._docker_client

        try:
            import docker

            self._docker_client = docker.from_env()
            return self._docker_client
        except Exception as e:
            raise IsolationViolationError(f"Docker daemon interface is unavailable: {e}") from e

    def build(self, config: BuildConfig, destination_root: Optional[Path] = None) -> BuildResult:
        """Executes reference build inside unprivileged container environment."""
        start_time = time.time()

        # 1. BuildConfig & SCM URL validation
        try:
            validate_scm_url(
                config.scm.scm_url,
                config.scm.commit_sha,
                config.scm.branch,
                config.scm.tag,
            )
            parsed_image = parse_and_validate_image_reference(config.toolchain.image_ref)
        except (SCMValidationError, ImageResolutionError, BuilderError) as e:
            return BuildResult(
                status=IsolationStatus.SYSTEM_ERROR,
                duration_seconds=time.time() - start_time,
                error_message=str(e),
            )
        except Exception as e:
            return BuildResult(
                status=IsolationStatus.SYSTEM_ERROR,
                duration_seconds=time.time() - start_time,
                error_message=f"Validation error: {e}",
            )

        # 2. Effective UID/GID mapping & workspace permission probe
        try:
            self._verify_workspace_access(config.out_dir)
        except (SecurityViolationError, IsolationViolationError) as e:
            return BuildResult(
                status=IsolationStatus.ISOLATION_VIOLATION,
                duration_seconds=time.time() - start_time,
                error_message=str(e),
            )

        client = self._get_client()

        # 3. Image resolution & repository manifest digest verification
        try:
            image_obj = client.images.get(config.toolchain.image_ref)
            repo_digests = getattr(image_obj, "attrs", {}).get("RepoDigests", [])
            if not verify_image_manifest_digest(client, parsed_image.digest, repo_digests):
                return BuildResult(
                    status=IsolationStatus.IMAGE_RESOLUTION_ERROR,
                    duration_seconds=time.time() - start_time,
                    error_message=(
                        f"Resolved image content digest does not match requested digest "
                        f"'{parsed_image.digest}' in RepoDigests: {repo_digests}"
                    ),
                )
        except Exception as e:
            return BuildResult(
                status=IsolationStatus.IMAGE_RESOLUTION_ERROR,
                duration_seconds=time.time() - start_time,
                error_message=f"Failed to resolve image '{config.toolchain.image_ref}': {e}",
            )

        container = None
        status = IsolationStatus.SYSTEM_ERROR
        exit_code = None
        stdout_buf = bytearray()
        stderr_buf = bytearray()
        stdout_truncated = False
        stderr_truncated = False
        artifact_paths = []
        error_msg = None

        try:
            # 4. docker.containers.create()
            mount_src = str(config.src_dir.resolve())
            mount_out = str(config.out_dir.resolve())

            container = client.containers.create(
                image=config.toolchain.image_ref,
                command=config.build_command,  # exec-form List[str]
                user="10001:10001",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                volumes={
                    mount_src: {"bind": "/workspace/src", "mode": "ro"},
                    mount_out: {"bind": "/workspace/out", "mode": "rw"},
                },
                tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=512m"},
                mem_limit=config.memory_limit_bytes,
                nano_cpus=int(config.cpu_limit * 1e9),
                pids_limit=512,
                environment=config.toolchain.environment,
                working_dir="/workspace",
            )

            # 5. docker.containers.inspect() created container security invariants
            container.reload()
            if not self._verify_container_invariants(container.attrs):
                status = IsolationStatus.ISOLATION_VIOLATION
                error_msg = "Created container failed security invariant inspection"
                try:
                    container.remove(force=True)
                except Exception:
                    pass
                container = None
                return BuildResult(
                    status=status,
                    duration_seconds=time.time() - start_time,
                    error_message=error_msg,
                )

            # 6. docker.containers.start()
            container.start()

            # 7. Streaming bounded log capture & wait with timeout
            wait_start = time.time()
            is_timeout = False

            while True:
                container.reload()
                curr_status = container.status
                elapsed = time.time() - wait_start

                if elapsed > config.timeout_seconds:
                    is_timeout = True
                    break

                if curr_status in ("exited", "dead"):
                    break

                time.sleep(0.1)

            if is_timeout:
                status = IsolationStatus.TIMEOUT
                error_msg = f"Build execution exceeded timeout boundary ({config.timeout_seconds}s)"
                try:
                    container.stop(timeout=1)
                except Exception:
                    try:
                        container.kill()
                    except Exception:
                        pass
            else:
                container.reload()
                exit_code = container.attrs.get("State", {}).get("ExitCode", -1)
                status = IsolationStatus.SUCCESS if exit_code == 0 else IsolationStatus.BUILD_FAILED

            # Fetch logs with bounded capture
            try:
                logs_raw = container.logs(stdout=True, stderr=True, stream=False)
                if isinstance(logs_raw, bytes):
                    if len(logs_raw) > MAX_STDOUT_SIZE:
                        stdout_buf = bytearray(logs_raw[:MAX_STDOUT_SIZE])
                        stdout_truncated = True
                    else:
                        stdout_buf = bytearray(logs_raw)
            except Exception:
                pass

            # 8. Stopped-state verification & artifact collection
            container.reload()
            is_running = container.status == "running"

            if status == IsolationStatus.SUCCESS and not is_running:
                dest = destination_root if destination_root else config.out_dir.parent / "artifacts"
                dest.mkdir(parents=True, exist_ok=True)
                try:
                    artifact_paths = collect_build_artifacts(
                        config.out_dir,
                        dest,
                        container_is_running=False,
                    )
                except (
                    SymlinkViolationError,
                    SpecialFileViolationError,
                    ArtifactCollectionError,
                    SecurityViolationError,
                ) as e:
                    status = IsolationStatus.ARTIFACT_COLLECTION_ERROR
                    error_msg = str(e)

        except Exception as e:
            if status == IsolationStatus.SYSTEM_ERROR:
                error_msg = f"Execution error: {e}"
        finally:
            # 9. Mandatory cleanup & teardown precedence
            cleanup_failed = False
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception as e:
                    cleanup_failed = True
                    cleanup_error_text = f"Teardown container removal failed: {e}"

            duration = time.time() - start_time

            # Precedence rule: zero-exit SUCCESS with cleanup failure MUST report SYSTEM_ERROR
            if status == IsolationStatus.SUCCESS and cleanup_failed:
                status = IsolationStatus.SYSTEM_ERROR
                error_msg = (
                    f"Build exited 0 but mandatory container teardown failed: {cleanup_error_text}"
                )
            elif cleanup_failed and error_msg is None:
                error_msg = cleanup_error_text

        return BuildResult(
            status=status,
            exit_code=exit_code,
            stdout=stdout_buf.decode("utf-8", errors="replace"),
            stderr=stderr_buf.decode("utf-8", errors="replace"),
            stdout_truncated=stdout_truncated,
            stderr_truncated=stderr_truncated,
            artifact_paths=artifact_paths,
            duration_seconds=duration,
            error_message=error_msg,
        )

    def _verify_workspace_access(self, out_dir: Path) -> None:
        """Verifies workspace directory mode is not world-writable (0777)."""
        resolved = out_dir.resolve()
        if os.name != "nt" and resolved.exists():
            st = resolved.stat()
            if st.st_mode & 0o002 != 0:  # World-writable check
                raise SecurityViolationError(
                    f"Workspace out directory '{resolved}' has unsafe "
                    "world-writable permissions (0777 prohibited)"
                )

    def _verify_container_invariants(self, attrs: dict) -> bool:
        """Inspects container HostConfig and Config attrs against required security invariants."""
        host_config = attrs.get("HostConfig", {})
        config = attrs.get("Config", {})

        # NetworkMode == "none"
        if host_config.get("NetworkMode") != "none":
            return False

        # ReadonlyRootfs == True
        if not host_config.get("ReadonlyRootfs"):
            return False

        # CapDrop contains ALL
        cap_drop = host_config.get("CapDrop", [])
        if "ALL" not in cap_drop:
            return False

        # SecurityOpt contains no-new-privileges
        sec_opt = host_config.get("SecurityOpt", [])
        if not any("no-new-privileges" in s for s in sec_opt):
            return False

        # User == "10001:10001"
        if config.get("User") != "10001:10001":
            return False

        # Privileged == False
        if host_config.get("Privileged"):
            return False

        # Tmpfs contains /tmp with nodev
        tmpfs = host_config.get("Tmpfs", {})
        if "/tmp" not in tmpfs or "nodev" not in tmpfs["/tmp"]:
            return False

        return True
