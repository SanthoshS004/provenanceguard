"""
Local Filesystem Storage Driver Implementation.
Used for local development, testing, and isolated environments.
Strictly prevents path traversal attacks when building target storage file paths.
"""

import shutil
from pathlib import Path
from typing import BinaryIO, Union

from provenanceguard.core.domain.exceptions import IngestionRejectedError
from provenanceguard.core.storage.ports import ObjectStorageDriver


class FilesystemStorageDriver(ObjectStorageDriver):
    """
    Concrete implementation of ObjectStorageDriver using local filesystem.
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir.resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)

    def _resolve_safe_path(self, storage_key: str) -> Path:
        """
        Safely resolves storage key against base directory.
        REJECTS path traversal attempts (`../`, absolute paths escaping base_dir).
        """
        clean_key = storage_key.lstrip("/\\")
        target_path = (self.base_dir / clean_key).resolve()

        # Enforce path traversal boundary check
        try:
            target_path.relative_to(self.base_dir)
        except ValueError as err:
            raise IngestionRejectedError(
                error_code="PG-1001",
                message=f"Path traversal attack detected in storage key: {storage_key}",
                details=["Target storage path escapes isolated storage directory root"],
            ) from err

        return target_path

    def put_object(
        self,
        storage_key: str,
        data: Union[BinaryIO, bytes],
        length: int,
        content_type: str = "application/octet-stream",
    ) -> str:
        target_path = self._resolve_safe_path(storage_key)
        target_path.parent.mkdir(parents=True, exist_ok=True)

        if isinstance(data, bytes):
            with open(target_path, "wb") as f:
                f.write(data)
        else:
            with open(target_path, "wb") as f:
                shutil.copyfileobj(data, f)

        return f"file://{target_path}"

    def get_object(self, storage_key: str) -> BinaryIO:
        target_path = self._resolve_safe_path(storage_key)
        if not target_path.exists():
            raise FileNotFoundError(f"Storage object not found: {storage_key}")

        return open(target_path, "rb")

    def delete_object(self, storage_key: str) -> bool:
        target_path = self._resolve_safe_path(storage_key)
        if target_path.exists():
            target_path.unlink()
            return True
        return False

    def exists(self, storage_key: str) -> bool:
        target_path = self._resolve_safe_path(storage_key)
        return target_path.exists()
