"""
OCI Whiteout Processing Module (.wh.<name> and .wh..wh..opq).
"""

import posixpath

from provenanceguard.analyzers.oci.oci_adapters import (
    OCIMalformedWhiteoutError,
    OCITraversalWhiteoutError,
)
from provenanceguard.analyzers.oci.oci_extraction import (
    VirtualRootFS,
    normalize_rootfs_path,
)


class OCIWhiteoutProcessor:
    """
    Processes OCI layer whiteout markers (.wh.<name> and .wh..wh..opq) on VirtualRootFS.
    """

    def apply_whiteouts(self, virtual_fs: VirtualRootFS) -> None:
        """
        Scans virtual_fs for whiteout files, applies deletions/opaque clears,
        and removes whiteout marker files from final virtual_fs.
        """
        whiteouts_to_process = []

        # Find all whiteout marker entries
        for path in list(virtual_fs.files.keys()):
            basename = posixpath.basename(path)
            if basename.startswith(".wh."):
                whiteouts_to_process.append(path)

        for whiteout_path in whiteouts_to_process:
            # Safe path normalization check
            try:
                clean_whiteout_path = normalize_rootfs_path(whiteout_path)
            except Exception as e:
                raise OCITraversalWhiteoutError(f"Whiteout path traversal error: {str(e)}") from e

            basename = posixpath.basename(clean_whiteout_path)
            parent_dir = posixpath.dirname(clean_whiteout_path)

            if basename == ".wh..wh..opq":
                # Opaque directory clear: clear all child entries in parent_dir
                self._apply_opaque_clear(virtual_fs, parent_dir)
            elif basename.startswith(".wh."):
                target_name = basename[4:]
                if not target_name:
                    raise OCIMalformedWhiteoutError(
                        f"Malformed whiteout filename '{basename}' with empty target"
                    )
                if "/" in target_name or ".." in target_name:
                    raise OCITraversalWhiteoutError(
                        f"Whiteout target contains path traversal: '{target_name}'"
                    )

                target_path = posixpath.join(parent_dir, target_name) if parent_dir else target_name
                self._apply_whiteout_delete(virtual_fs, target_path)

            # Remove whiteout marker file from virtual_fs
            if whiteout_path in virtual_fs.files:
                del virtual_fs.files[whiteout_path]

    def _apply_whiteout_delete(self, virtual_fs: VirtualRootFS, target_path: str) -> None:
        """Deletes target_path and all nested children from virtual_fs (NEVER following symlinks)."""
        # Delete file entry if matches exactly
        if target_path in virtual_fs.files:
            del virtual_fs.files[target_path]

        # Delete symlink entry if matches exactly
        if target_path in virtual_fs.symlinks:
            del virtual_fs.symlinks[target_path]

        # Delete directory entry if matches exactly
        if target_path in virtual_fs.directories:
            del virtual_fs.directories[target_path]

        # Recursively delete any nested children under target_path directory
        prefix = f"{target_path}/"
        for p in list(virtual_fs.files.keys()):
            if p.startswith(prefix):
                del virtual_fs.files[p]

        for p in list(virtual_fs.directories.keys()):
            if p.startswith(prefix):
                del virtual_fs.directories[p]

        for p in list(virtual_fs.symlinks.keys()):
            if p.startswith(prefix):
                del virtual_fs.symlinks[p]

    def _apply_opaque_clear(self, virtual_fs: VirtualRootFS, parent_dir: str) -> None:
        """Clears all entries inside parent_dir (NEVER following symlinks)."""
        prefix = f"{parent_dir}/" if parent_dir else ""

        for p in list(virtual_fs.files.keys()):
            if (parent_dir == "" and "/" not in p) or (prefix and p.startswith(prefix)):
                del virtual_fs.files[p]

        for p in list(virtual_fs.directories.keys()):
            if p != parent_dir:
                if (parent_dir == "" and "/" not in p) or (prefix and p.startswith(prefix)):
                    del virtual_fs.directories[p]

        for p in list(virtual_fs.symlinks.keys()):
            if (parent_dir == "" and "/" not in p) or (prefix and p.startswith(prefix)):
                del virtual_fs.symlinks[p]
