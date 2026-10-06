"""
MinIO / S3 Object Storage Driver Implementation.
Concrete infrastructure adapter using MinIO SDK client.
DEPENDENCY ISOLATION: Located strictly under infrastructure/ to isolate third-party
minio SDK dependencies.
"""

import io
from typing import BinaryIO, Union

from minio import Minio
from minio.error import S3Error

from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.core.storage.ports import ObjectStorageDriver


class MinIOStorageDriver(ObjectStorageDriver):
    """
    Concrete ObjectStorageDriver adapter connecting to S3-compatible object storage (MinIO/AWS S3).
    """

    def __init__(
        self,
        endpoint: str,
        access_key: str,
        secret_key: str,
        bucket_name: str,
        secure: bool = False,
    ):
        self.endpoint = endpoint
        self.bucket_name = bucket_name
        self.client = Minio(
            endpoint=endpoint.replace("http://", "").replace("https://", ""),
            access_key=access_key,
            secret_key=secret_key,
            secure=secure,
        )
        self._ensure_bucket()

    def _ensure_bucket(self):
        try:
            if not self.client.bucket_exists(self.bucket_name):
                self.client.make_bucket(self.bucket_name)
        except Exception:
            # Bucket creation or check deferred to runtime connection
            pass

    def _validate_key(self, storage_key: str) -> str:
        clean_key = storage_key.lstrip("/\\")
        if ".." in clean_key:
            raise IngestionRejectedError(
                error_code="PG-1001",
                message=f"Path traversal attempt detected in S3 storage key: {storage_key}",
                details=["Storage key contains prohibited parent directory traversals ('..')"],
            )
        return clean_key

    def put_object(
        self,
        storage_key: str,
        data: Union[BinaryIO, bytes],
        length: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        key = self._validate_key(storage_key)

        if isinstance(data, bytes):
            stream = io.BytesIO(data)
            stream_len = len(data)
        else:
            stream = data
            stream_len = length

        self.client.put_object(
            bucket_name=self.bucket_name,
            object_name=key,
            data=stream,
            length=stream_len,
            content_type=content_type,
        )
        return f"s3://{self.bucket_name}/{key}"

    def get_object(self, storage_key: str) -> BinaryIO:
        key = self._validate_key(storage_key)
        try:
            response = self.client.get_object(self.bucket_name, key)
            return io.BytesIO(response.read())
        except S3Error as err:
            raise FileNotFoundError(f"S3 Object not found: {storage_key} ({err})") from err

    def delete_object(self, storage_key: str) -> bool:
        key = self._validate_key(storage_key)
        try:
            self.client.remove_object(self.bucket_name, key)
            return True
        except S3Error:
            return False

    def exists(self, storage_key: str) -> bool:
        key = self._validate_key(storage_key)
        try:
            self.client.stat_object(self.bucket_name, key)
            return True
        except S3Error:
            return False
