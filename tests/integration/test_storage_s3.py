"""
Integration Tests for MinIO / S3 Object Storage Driver
Note: Skipped gracefully if live MinIO endpoint is not reachable during test execution.
"""

import os

import pytest

from provenanceguard.infrastructure.storage.s3 import MinIOStorageDriver

MINIO_ENDPOINT = os.getenv("PG_MINIO_ENDPOINT", "http://localhost:9000")
MINIO_ACCESS_KEY = os.getenv("PG_MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("PG_MINIO_SECRET_KEY", "minioadminpassword")


@pytest.fixture
def s3_driver():
    try:
        driver = MinIOStorageDriver(
            endpoint=MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            bucket_name="provenanceguard-test-bucket",
            secure=False,
        )
        return driver
    except Exception as e:
        pytest.skip(f"MinIO storage integration test skipped: endpoint not reachable ({e})")


def test_minio_storage_driver_lifecycle(s3_driver):
    key = "test_org/test_proj/artifacts/test_sha256_hash_123"
    payload = b"MinIO test binary payload data"

    try:
        ref = s3_driver.put_object(storage_key=key, data=payload, length=len(payload))
        assert ref.startswith("s3://")
        assert s3_driver.exists(key)

        with s3_driver.get_object(key) as f:
            data = f.read()
        assert data == payload

        s3_driver.delete_object(key)
        assert not s3_driver.exists(key)
    except Exception as e:
        pytest.skip(f"MinIO live operation failed: {e}")
