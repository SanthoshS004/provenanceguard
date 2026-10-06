"""
Abstract Storage Ports / Interface for ProvenanceGuard Object Storage.
DEPENDENCY INVARIANT: The core domain and ports import ZERO third-party storage libraries
(boto3, minio).
"""

from abc import ABC, abstractmethod
from typing import BinaryIO, Union


class ObjectStorageDriver(ABC):
    """
    Abstract interface for enterprise object storage drivers.
    """

    @abstractmethod
    def put_object(
        self,
        storage_key: str,
        data: Union[BinaryIO, bytes],
        length: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        """
        Stores an object payload at the specified tenant-isolated storage key.
        :param storage_key: Tenant-isolated storage path (<org_id>/<project_id>/artifacts/<sha256>).
        :param data: Binary stream or bytes payload.
        :param length: Total byte size.
        :param content_type: MIME media type string.
        :return: Authoritative storage reference string.
        """
        pass

    @abstractmethod
    def get_object(self, storage_key: str) -> BinaryIO:
        """
        Retrieves binary stream for the specified storage key.
        """
        pass

    @abstractmethod
    def delete_object(self, storage_key: str) -> bool:
        """
        Deletes object at specified storage key.
        """
        pass

    @abstractmethod
    def exists(self, storage_key: str) -> bool:
        """
        Checks if storage key exists.
        """
        pass
