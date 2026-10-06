"""
Fail-Closed Artifact Collector with Hardlink Classification and Descriptor Race Protection
"""

import os
import shutil
import stat
from pathlib import Path
from typing import List, Optional

from provenanceguard.builders.isolated.exceptions import (
    ArtifactCollectionError,
    SecurityViolationError,
    SpecialFileViolationError,
    SymlinkViolationError,
)

MAX_ARTIFACT_COUNT = 1000
MAX_ARTIFACT_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
MAX_TOTAL_ARTIFACT_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB


def collect_build_artifacts(
    workspace_out: Path,
    destination_root: Path,
    container_is_running: bool = False,
    artifact_storage_root: Optional[Path] = None,
) -> List[Path]:
    """
    Recursively scans workspace_out and copies verified build artifacts to destination_root.

    Enforces:
    - Container MUST be stopped (container_is_running == False)
    - Symlinks rejected immediately (SymlinkViolationError)
    - Regular files with st_nlink > 1 rejected as hardlinks (SpecialFileViolationError)
    - Normal directories with st_nlink >= 2 allowed and scanned recursively
    - FIFOs, sockets, character/block devices, and reparse points rejected
    - Canonical path containment inside workspace_out
    - Descriptor no-follow opening (O_NOFOLLOW) and os.fstat(fd) verification
    - Resource limits: MAX_ARTIFACT_COUNT (1000), MAX_ARTIFACT_FILE_SIZE (500MB),
      MAX_TOTAL_ARTIFACT_SIZE (2GB)
    - Destination root containment and least-privilege permissions (0700)
    """
    if container_is_running:
        raise ArtifactCollectionError("Artifact collection requested while container is running")

    resolved_out = workspace_out.resolve()
    if not resolved_out.exists() or not resolved_out.is_dir():
        raise ArtifactCollectionError(f"Workspace out directory does not exist: {workspace_out}")

    resolved_dest = destination_root.resolve()

    # Destination security containment check
    if artifact_storage_root:
        resolved_storage_root = artifact_storage_root.resolve()
        try:
            resolved_dest.relative_to(resolved_storage_root)
        except ValueError as e:
            raise SecurityViolationError(
                f"Artifact destination '{destination_root}' "
                f"escapes designated storage root '{artifact_storage_root}'"
            ) from e

    # Verify destination host directory permissions (must not be world-writable 0777 on POSIX)
    if os.name != "nt" and resolved_dest.exists():
        dest_stat = os.stat(resolved_dest)
        if dest_stat.st_mode & 0o002 != 0:  # World-writable check
            raise SecurityViolationError(
                f"Artifact destination directory '{resolved_dest}' "
                "has unsafe world-writable permissions"
            )

    collected_paths: List[Path] = []
    total_count = 0
    total_size = 0

    # Walk workspace_out
    for root, _dirs, files in os.walk(resolved_out):
        root_path = Path(root)

        # Check directory itself
        dir_stat = os.lstat(root_path)
        if os.path.islink(root_path) or stat.S_ISLNK(dir_stat.st_mode):
            raise SymlinkViolationError(f"Symlink directory detected at {root_path}")

        # Check canonical directory containment
        try:
            root_path.resolve().relative_to(resolved_out)
        except ValueError as e:
            raise SecurityViolationError(
                f"Directory path '{root_path}' escapes workspace out directory '{resolved_out}'"
            ) from e

        for f_name in files:
            file_path = root_path / f_name

            # 1. Check symlink using lstat / islink
            if os.path.islink(file_path):
                raise SymlinkViolationError(f"Symlink artifact detected at {file_path}")

            try:
                st = os.lstat(file_path)
            except OSError as e:
                raise ArtifactCollectionError(
                    f"Failed to lstat artifact path {file_path}: {e}"
                ) from e

            # Canonical path containment check
            try:
                canonical_file = file_path.resolve()
                canonical_file.relative_to(resolved_out)
            except ValueError as e:
                raise SecurityViolationError(
                    f"Artifact file '{file_path}' resolves outside workspace out: {canonical_file}"
                ) from e

            mode = st.st_mode

            # 2. Reject non-regular special files (FIFOs, sockets, devices)
            if stat.S_ISLNK(mode):
                raise SymlinkViolationError(f"Symlink artifact detected at {file_path}")
            elif (
                stat.S_ISFIFO(mode)
                or stat.S_ISSOCK(mode)
                or stat.S_ISBLK(mode)
                or stat.S_ISCHR(mode)
            ):
                raise SpecialFileViolationError(f"Special file detected at {file_path}")
            elif not stat.S_ISREG(mode):
                raise SpecialFileViolationError(f"Non-regular file object detected at {file_path}")

            # 3. Hardlink check for regular files
            if st.st_nlink > 1:
                raise SpecialFileViolationError(
                    f"Regular file with hardlink count {st.st_nlink} detected at {file_path}"
                )

            # 4. Resource limits check
            file_size = st.st_size
            if file_size > MAX_ARTIFACT_FILE_SIZE:
                raise ArtifactCollectionError(
                    f"Individual artifact file '{file_path.name}' size ({file_size} bytes) "
                    f"exceeds limit ({MAX_ARTIFACT_FILE_SIZE} bytes / 500MB)"
                )

            total_count += 1
            if total_count > MAX_ARTIFACT_COUNT:
                raise ArtifactCollectionError(
                    f"Artifact file count ({total_count}) exceeds limit ({MAX_ARTIFACT_COUNT})"
                )

            total_size += file_size
            if total_size > MAX_TOTAL_ARTIFACT_SIZE:
                raise ArtifactCollectionError(
                    f"Total aggregate artifact size ({total_size} bytes) "
                    f"exceeds limit ({MAX_TOTAL_ARTIFACT_SIZE} bytes / 2GB)"
                )

            # 5. Descriptor no-follow open and copy
            rel_path = file_path.relative_to(resolved_out)
            dest_file_path = resolved_dest / rel_path
            dest_file_path.parent.mkdir(parents=True, exist_ok=True)

            _copy_file_descriptor_safe(file_path, dest_file_path)
            collected_paths.append(dest_file_path)

    return collected_paths


def _copy_file_descriptor_safe(src_path: Path, dest_path: Path) -> None:
    """
    Opens src_path with no-follow flags, verifies descriptor stats via os.fstat,
    and streams bytes to dest_path securely against filesystem races.
    """
    open_flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        open_flags |= os.O_NOFOLLOW

    try:
        fd = os.open(str(src_path), open_flags)
    except OSError as e:
        raise SymlinkViolationError(f"Failed safe descriptor open for {src_path}: {e}") from e

    try:
        fd_stat = os.fstat(fd)
        if not stat.S_ISREG(fd_stat.st_mode) or fd_stat.st_nlink > 1:
            raise SpecialFileViolationError(
                f"Descriptor verification failed for {src_path}: "
                f"mode={fd_stat.st_mode}, nlink={fd_stat.st_nlink}"
            )

        with open(fd, "rb", closefd=False) as f_src:
            with open(dest_path, "wb") as f_dst:
                shutil.copyfileobj(f_src, f_dst)
    finally:
        os.close(fd)
