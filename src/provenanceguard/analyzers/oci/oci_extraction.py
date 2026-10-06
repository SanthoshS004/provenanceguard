"""
Hardened Layer Extraction Engine & In-Memory Virtual RootFS Builder.
"""

import gzip
import hashlib
import io
import posixpath
import tarfile
from typing import Dict, Set, Tuple

from provenanceguard.analyzers.oci.oci_adapters import (
    OCIError,
    OCIInvalidHardlinkError,
    OCIInvalidTarHeaderError,
    OCIMalformedLayerError,
    OCIMediaTypeMismatchError,
    OCIResourceExceededError,
    OCIUnsupportedCompressionError,
)
from provenanceguard.analyzers.oci.oci_spec import (
    DOCKER_LAYER_GZIP_MEDIA_TYPE,
    OCI_LAYER_GZIP_MEDIA_TYPE,
    OCI_LAYER_TAR_MEDIA_TYPE,
    NormalizedOCIImage,
    SymlinkMetadata,
)

# Limits
MAX_LAYER_COUNT = 100
MAX_COMPRESSED_LAYER_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB
MAX_UNCOMPRESSED_LAYER_SIZE = 2 * 1024 * 1024 * 1024  # 2 GB
MAX_CUMULATIVE_ROOTFS_SIZE = 4 * 1024 * 1024 * 1024  # 4 GB
MAX_ROOTFS_FILE_COUNT = 100_000
MAX_DECOMPRESSION_RATIO = 10.0


class VirtualFile:
    """In-memory representation of a regular file in virtual rootfs."""

    def __init__(self, path: str, content: bytes, mode: int = 0o644):
        self.path = path
        self.content = content
        self.size = len(content)
        self.sha256 = hashlib.sha256(content).hexdigest()
        self.mode = mode


class VirtualDirectory:
    """In-memory representation of a directory in virtual rootfs."""

    def __init__(self, path: str, mode: int = 0o755):
        self.path = path
        self.mode = mode


class VirtualRootFS:
    """In-memory virtual rootfs tree."""

    def __init__(self):
        self.files: Dict[str, VirtualFile] = {}
        self.directories: Dict[str, VirtualDirectory] = {"": VirtualDirectory("")}
        self.symlinks: Dict[str, SymlinkMetadata] = {}

    def get_materialized_paths(self) -> Set[str]:
        """Returns set of all safely materialized file and directory paths."""
        paths = set(self.files.keys()) | set(self.directories.keys())
        return paths


def normalize_rootfs_path(raw_path: str) -> str:
    """
    Normalizes path to clean POSIX relative path from rootfs root.
    Rejects '..' traversal out of root or null byte injection.
    """
    if "\x00" in raw_path:
        raise OCIError("Path contains null bytes")

    clean = posixpath.normpath(raw_path)
    if clean.startswith("/") or clean.startswith("\\"):
        clean = clean.lstrip("/\\")
    clean = posixpath.normpath(clean)

    if clean == "." or clean == "":
        return ""

    if clean.startswith("..") or "/../" in f"/{clean}/":
        raise OCIError(f"Path traversal detected in path '{raw_path}'")

    return clean


class OCIHardenedExtractor:
    """
    Hardened layer extractor building an in-memory VirtualRootFS.
    """

    def extract_layers(
        self,
        normalized_image: NormalizedOCIImage,
    ) -> VirtualRootFS:
        """Extracts and layer-combines layers into VirtualRootFS."""
        manifest = normalized_image.manifest
        config = normalized_image.config
        blobs = normalized_image.raw_blobs

        if len(manifest.layers) > MAX_LAYER_COUNT:
            raise OCIResourceExceededError(
                f"Layer count ({len(manifest.layers)}) exceeds limit ({MAX_LAYER_COUNT})"
            )

        virtual_fs = VirtualRootFS()
        cumulative_rootfs_size = 0

        for idx, layer_desc in enumerate(manifest.layers):
            layer_digest = layer_desc.digest
            expected_diff_id = config.rootfs.diff_ids[idx]

            layer_bytes = blobs[layer_digest]

            # 1. Validate compressed layer size
            if len(layer_bytes) > MAX_COMPRESSED_LAYER_SIZE:
                raise OCIResourceExceededError(
                    f"Compressed layer {idx} size ({len(layer_bytes)} bytes) exceeds limit ({MAX_COMPRESSED_LAYER_SIZE})"
                )

            # 2. Decompress stream & validate magic header
            uncompressed_tar_bytes, actual_diff_id = self._decompress_layer(
                layer_desc.mediaType, layer_bytes
            )

            # 3. Verify uncompressed diff_id matches config
            if actual_diff_id.lower() != expected_diff_id.lower():
                raise OCIMalformedLayerError(
                    f"Uncompressed layer {idx} diff_id mismatch: computed '{actual_diff_id}' "
                    f"does not match config '{expected_diff_id}'"
                )

            # 4. Extract tar stream into virtual_fs
            cumulative_rootfs_size = self._extract_tar_stream(
                uncompressed_tar_bytes, virtual_fs, cumulative_rootfs_size
            )

        return virtual_fs

    def _decompress_layer(
        self,
        media_type: str,
        compressed_bytes: bytes,
    ) -> Tuple[bytes, str]:
        """
        Decompresses layer stream according to mediaType & magic header.
        Returns (uncompressed_tar_bytes, uncompressed_diff_id_sha256).
        """
        compressed_size = len(compressed_bytes)

        # Magic header check
        is_gzip = compressed_bytes.startswith(b"\x1f\x8b")

        if media_type in (OCI_LAYER_GZIP_MEDIA_TYPE, DOCKER_LAYER_GZIP_MEDIA_TYPE):
            if not is_gzip:
                raise OCIMediaTypeMismatchError(
                    f"Declared mediaType '{media_type}' but payload missing gzip magic header 0x1f 0x8b"
                )
        elif media_type == OCI_LAYER_TAR_MEDIA_TYPE:
            if is_gzip:
                raise OCIMediaTypeMismatchError(
                    f"Declared mediaType '{media_type}' (uncompressed tar) but payload contains gzip magic header"
                )
        elif "zstd" in media_type or "bzip2" in media_type or "xz" in media_type:
            raise OCIUnsupportedCompressionError(
                f"Unsupported layer compression mediaType '{media_type}'"
            )

        if is_gzip:
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(compressed_bytes), mode="rb") as gz:
                    uncompressed_bytes = gz.read(MAX_UNCOMPRESSED_LAYER_SIZE + 1)
            except Exception as e:
                raise OCIMalformedLayerError(f"Gzip decompression failed: {str(e)}") from e
        else:
            uncompressed_bytes = compressed_bytes

        uncompressed_size = len(uncompressed_bytes)
        if uncompressed_size > MAX_UNCOMPRESSED_LAYER_SIZE:
            raise OCIResourceExceededError(
                f"Uncompressed layer size ({uncompressed_size} bytes) exceeds limit ({MAX_UNCOMPRESSED_LAYER_SIZE})"
            )

        ratio = uncompressed_size / max(compressed_size, 1)
        if ratio > MAX_DECOMPRESSION_RATIO and uncompressed_size > 10 * 1024 * 1024:
            raise OCIResourceExceededError(
                f"Layer decompression ratio ({ratio:.2f}:1) exceeds limit ({MAX_DECOMPRESSION_RATIO}:1)"
            )

        diff_id = f"sha256:{hashlib.sha256(uncompressed_bytes).hexdigest()}"
        return uncompressed_bytes, diff_id

    def _extract_tar_stream(
        self,
        tar_bytes: bytes,
        virtual_fs: VirtualRootFS,
        current_cumulative_size: int,
    ) -> int:
        """Extracts tar stream into virtual_fs with strict security checks."""
        try:
            tar = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*")
        except Exception as e:
            raise OCIMalformedLayerError(f"Failed to parse layer tar archive: {str(e)}") from e

        cumulative_size = current_cumulative_size

        for member in tar.getmembers():
            raw_name = member.name
            try:
                clean_path = normalize_rootfs_path(raw_name)
            except OCIError as e:
                raise OCIInvalidTarHeaderError(f"Tar header path traversal error: {str(e)}") from e

            # Check special bit flags (setuid 0o4000, setgid 0o2000)
            if member.mode & 0o6000:
                raise OCIError(f"Rejection: file '{clean_path}' has setuid/setgid bits set")

            # Check special device files
            if member.isdev() or member.ischr() or member.isblk() or member.isfifo():
                raise OCIError(
                    f"Rejection: special device file/FIFO/socket '{clean_path}' in layer tar"
                )

            if member.isdir():
                if clean_path:
                    virtual_fs.directories[clean_path] = VirtualDirectory(
                        clean_path, mode=member.mode
                    )

            elif member.issym():
                target = member.linkname
                if "\x00" in target:
                    raise OCIInvalidTarHeaderError(
                        f"Symlink target contains null bytes: '{target}'"
                    )

                # Check if symlink target is outside rootfs
                is_outside = False
                if target.startswith("/"):
                    is_outside = True
                else:
                    # Resolve relative target against directory containing clean_path
                    parent_dir = posixpath.dirname(clean_path)
                    resolved = posixpath.normpath(posixpath.join(parent_dir, target))
                    if resolved.startswith("..") or "/../" in f"/{resolved}/":
                        is_outside = True

                # Store as INERT metadata only; NEVER follow or resolve
                virtual_fs.symlinks[clean_path] = SymlinkMetadata(
                    path=clean_path,
                    target=target,
                    is_outside_root=is_outside,
                )

            elif member.islnk():
                # Hardlink validation
                raw_target = member.linkname
                try:
                    clean_target = normalize_rootfs_path(raw_target)
                except OCIError as e:
                    raise OCIInvalidHardlinkError(
                        f"Hardlink target traversal error: {str(e)}"
                    ) from e

                materialized = virtual_fs.get_materialized_paths()
                if clean_target not in materialized:
                    raise OCIInvalidHardlinkError(
                        f"Hardlink '{clean_path}' points to unmaterialized path '{clean_target}'"
                    )

                if clean_target in virtual_fs.symlinks:
                    raise OCIInvalidHardlinkError(
                        f"Hardlink '{clean_path}' points to a symlink '{clean_target}'"
                    )

                # Materialize hardlink by duplicating target entry
                if clean_target in virtual_fs.files:
                    target_file = virtual_fs.files[clean_target]
                    virtual_fs.files[clean_path] = VirtualFile(
                        clean_path, target_file.content, mode=member.mode
                    )

            elif member.isfile() or member.isreg():
                # Extract regular file payload
                f_obj = tar.extractfile(member)
                if f_obj is None:
                    file_content = b""
                else:
                    file_content = f_obj.read()

                content_len = len(file_content)
                cumulative_size += content_len

                if cumulative_size > MAX_CUMULATIVE_ROOTFS_SIZE:
                    raise OCIResourceExceededError(
                        f"Cumulative rootfs size ({cumulative_size} bytes) exceeds limit ({MAX_CUMULATIVE_ROOTFS_SIZE})"
                    )

                total_files = len(virtual_fs.files) + len(virtual_fs.symlinks)
                if total_files > MAX_ROOTFS_FILE_COUNT:
                    raise OCIResourceExceededError(
                        f"Total rootfs file count ({total_files}) exceeds limit ({MAX_ROOTFS_FILE_COUNT})"
                    )

                virtual_fs.files[clean_path] = VirtualFile(
                    clean_path, file_content, mode=member.mode
                )

        return cumulative_size
