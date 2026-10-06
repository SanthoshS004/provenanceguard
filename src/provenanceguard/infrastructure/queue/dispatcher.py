"""Abstract Task Dispatcher interface and validated Job Payload schema."""

import json
import uuid
from abc import ABC, abstractmethod
from datetime import datetime, timezone

from pydantic import BaseModel, ConfigDict, Field


class PayloadSecurityError(ValueError):
    """Raised when a job payload contains prohibited secret keys or data."""


PROHIBITED_SECRET_KEYS = {
    "password",
    "api_key",
    "apikey",
    "secret",
    "bearer",
    "private_key",
    "token",
    "credential",
    "access_token",
    "refresh_token",
}


class JobPayload(BaseModel):
    """Versioned, bounded, validated job payload for asynchronous verification tasks."""

    schema_version: int = Field(default=1, ge=1, le=1)
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    verification_run_id: uuid.UUID
    organization_id: uuid.UUID
    project_id: uuid.UUID
    attempt: int = Field(default=1, ge=1, le=3)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    model_config = ConfigDict(extra="forbid", frozen=True)

    @classmethod
    def validate_dict_security(cls, data: dict) -> None:
        """Inspects input dictionary for any prohibited secret keys."""

        def _scan_keys(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    key_lower = str(k).lower()
                    if any(secret_kw in key_lower for secret_kw in PROHIBITED_SECRET_KEYS):
                        raise PayloadSecurityError(
                            "Prohibited secret key detected in job payload dictionary."
                        )
                    _scan_keys(v)
            elif isinstance(obj, list):
                for item in obj:
                    _scan_keys(item)

        _scan_keys(data)

    def to_json_bytes(self) -> bytes:
        """Serializes payload to UTF-8 JSON bytes, enforcing 16KB max payload limit."""
        data_dict = self.model_dump(mode="json")
        self.validate_dict_security(data_dict)
        raw_bytes = json.dumps(data_dict).encode("utf-8")
        if len(raw_bytes) > 16384:  # 16 KB
            raise PayloadSecurityError("Job payload exceeds maximum allowed size bound of 16KB.")
        return raw_bytes


class TaskDispatcher(ABC):
    """Abstract interface for asynchronous job dispatch."""

    @abstractmethod
    async def dispatch_verification_job(self, payload: JobPayload) -> str:
        """Dispatches a job payload to the async task queue. Returns job ID."""
        ...
