"""
Unit Contract Tests for Local Filesystem Storage Driver
Tests storage contract & path traversal prevention without live services.
"""

import pytest

from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.infrastructure.storage.filesystem import FilesystemStorageDriver


def test_filesystem_storage_lifecycle(tmp_path):
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage_root")
    sha_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    key = f"org_acme/proj_pay/artifacts/{sha_hash}"

    assert not driver.exists(key)

    payload = b"binary payload content"
    ref = driver.put_object(storage_key=key, data=payload, length=len(payload))

    assert ref.startswith("file://")
    assert driver.exists(key)

    with driver.get_object(key) as f:
        content = f.read()
    assert content == payload

    assert driver.delete_object(key) is True
    assert not driver.exists(key)


def test_filesystem_storage_path_traversal_rejection(tmp_path):
    driver = FilesystemStorageDriver(base_dir=tmp_path / "storage_root")
    malicious_key = "../../etc/passwd"

    with pytest.raises(IngestionRejectedError) as exc_info:
        driver.put_object(storage_key=malicious_key, data=b"data", length=4)

    assert "Path traversal attack detected" in str(exc_info.value)
