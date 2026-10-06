"""
Unit tests for OCI Whiteout Processing (.wh.<name> and .wh..wh..opq).
"""

from provenanceguard.analyzers.oci.oci_extraction import (
    VirtualFile,
    VirtualRootFS,
)
from provenanceguard.analyzers.oci.oci_whiteout import OCIWhiteoutProcessor


def test_whiteout_file_deletion():
    processor = OCIWhiteoutProcessor()
    virtual_fs = VirtualRootFS()

    virtual_fs.files["etc/config.txt"] = VirtualFile("etc/config.txt", b"old config")
    # Whiteout marker file .wh.config.txt inside etc/
    virtual_fs.files["etc/.wh.config.txt"] = VirtualFile("etc/.wh.config.txt", b"")

    processor.apply_whiteouts(virtual_fs)

    assert "etc/config.txt" not in virtual_fs.files
    assert "etc/.wh.config.txt" not in virtual_fs.files


def test_opaque_directory_clearing():
    processor = OCIWhiteoutProcessor()
    virtual_fs = VirtualRootFS()

    virtual_fs.files["var/log/app.log"] = VirtualFile("var/log/app.log", b"log data")
    virtual_fs.files["var/log/sys.log"] = VirtualFile("var/log/sys.log", b"sys data")
    # Opaque whiteout marker inside var/log/
    virtual_fs.files["var/log/.wh..wh..opq"] = VirtualFile("var/log/.wh..wh..opq", b"")

    processor.apply_whiteouts(virtual_fs)

    assert "var/log/app.log" not in virtual_fs.files
    assert "var/log/sys.log" not in virtual_fs.files
    assert "var/log/.wh..wh..opq" not in virtual_fs.files
