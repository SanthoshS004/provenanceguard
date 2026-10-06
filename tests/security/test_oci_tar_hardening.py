"""
Security tests for Hardened Tar Extraction, Symlinks & Virtual RootFS.
"""

import io
import tarfile

import pytest

from provenanceguard.analyzers.oci.oci_adapters import OCIInvalidHardlinkError
from provenanceguard.analyzers.oci.oci_extraction import (
    OCIHardenedExtractor,
    VirtualRootFS,
)


def test_inert_symlink_metadata_never_followed():
    extractor = OCIHardenedExtractor()
    virtual_fs = VirtualRootFS()

    # Create tar bytes containing a relative safe symlink and an absolute outside symlink
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # Safe symlink
        ti1 = tarfile.TarInfo(name="lib/libfoo.so")
        ti1.type = tarfile.SYMTYPE
        ti1.linkname = "libfoo.so.1"
        tar.addfile(ti1)

        # Malicious outside-root symlink targeting /etc/shadow
        ti2 = tarfile.TarInfo(name="var/log/sym_shadow")
        ti2.type = tarfile.SYMTYPE
        ti2.linkname = "/etc/shadow"
        tar.addfile(ti2)

    tar_bytes = buf.getvalue()
    extractor._extract_tar_stream(tar_bytes, virtual_fs, 0)

    # Verify symlinks are stored strictly as inert SymlinkMetadata records
    assert "lib/libfoo.so" in virtual_fs.symlinks
    assert virtual_fs.symlinks["lib/libfoo.so"].target == "libfoo.so.1"
    assert not virtual_fs.symlinks["lib/libfoo.so"].is_outside_root

    assert "var/log/sym_shadow" in virtual_fs.symlinks
    assert virtual_fs.symlinks["var/log/sym_shadow"].target == "/etc/shadow"
    assert virtual_fs.symlinks["var/log/sym_shadow"].is_outside_root

    # Verify symlink path was NOT followed or materialized as an OS symlink / file
    assert "lib/libfoo.so" not in virtual_fs.files


def test_duplicate_tar_entry_deterministic_overwrite():
    extractor = OCIHardenedExtractor()
    virtual_fs = VirtualRootFS()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        ti1 = tarfile.TarInfo(name="etc/config.txt")
        ti1.size = len(b"old content")
        tar.addfile(ti1, io.BytesIO(b"old content"))

        ti2 = tarfile.TarInfo(name="etc/config.txt")
        ti2.size = len(b"new content")
        tar.addfile(ti2, io.BytesIO(b"new content"))

    extractor._extract_tar_stream(buf.getvalue(), virtual_fs, 0)
    assert virtual_fs.files["etc/config.txt"].content == b"new content"


def test_hardlink_to_materialized_path_success():
    extractor = OCIHardenedExtractor()
    virtual_fs = VirtualRootFS()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # File 1
        ti1 = tarfile.TarInfo(name="usr/bin/python")
        ti1.size = len(b"python binary")
        tar.addfile(ti1, io.BytesIO(b"python binary"))

        # Hardlink python3 -> usr/bin/python
        ti2 = tarfile.TarInfo(name="usr/bin/python3")
        ti2.type = tarfile.LNKTYPE
        ti2.linkname = "usr/bin/python"
        tar.addfile(ti2)

    extractor._extract_tar_stream(buf.getvalue(), virtual_fs, 0)
    assert "usr/bin/python3" in virtual_fs.files
    assert virtual_fs.files["usr/bin/python3"].content == b"python binary"


def test_hardlink_to_unmaterialized_or_traversal_path_rejection():
    extractor = OCIHardenedExtractor()
    virtual_fs = VirtualRootFS()

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        # Hardlink pointing to non-existent target
        ti1 = tarfile.TarInfo(name="usr/bin/bad_link")
        ti1.type = tarfile.LNKTYPE
        ti1.linkname = "usr/bin/nonexistent"
        tar.addfile(ti1)

    with pytest.raises(OCIInvalidHardlinkError):
        extractor._extract_tar_stream(buf.getvalue(), virtual_fs, 0)
