"""
Generic Artifact Data Models
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class MediaType(str, Enum):
    ELF = "application/vnd.elf"
    OCI_TAR = "application/vnd.oci.image.layer.v1.tar+gzip"
    SPDX_JSON = "application/spdx+json"
    CYCLONEDX_JSON = "application/vnd.cyclonedx+json"
    UNKNOWN = "application/octet-stream"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFYING = "VERIFYING"
    PASS = "PASS"
    PASS_WITH_WARNING = "PASS_WITH_WARNING"
    BLOCK = "BLOCK"


class Artifact(BaseModel):
    """
    Generic Artifact model abstraction independent of specific binary formats.
    """

    id: str
    project_id: str
    name: str
    version: str
    media_type: MediaType
    digest_sha256: str
    size_bytes: int
    source_reference: Optional[str] = None
    build_reference: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    storage_reference: Optional[str] = None
    signature_status: str = "UNCHECKED"
    provenance_status: str = "UNCHECKED"
    verification_status: VerificationStatus = VerificationStatus.UNVERIFIED
