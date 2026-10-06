"""Audit Log Tamper-Evident Integrity Domain Module.

Implements organization-scoped canonical audit event serialization,
SHA-256 hash-chain calculation, trusted checkpoint verification,
and anomaly detection for record modification, link breakage,
sequence gaps, and tail deletion.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Sequence

GENESIS_PREVIOUS_HASH: str = "0000000000000000000000000000000000000000000000000000000000000000"


def format_utc_timestamp(dt: datetime | str) -> str:
    """Formats datetime or timestamp string to deterministic ISO-8601 UTC string."""
    if isinstance(dt, str):
        try:
            parsed = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def canonicalize_audit_entry(
    version: str,
    sequence_number: int,
    previous_hash: str,
    organization_id: uuid.UUID | str,
    actor_id: str,
    action: str,
    resource: str,
    result: str,
    timestamp_utc: datetime | str,
    metadata_json: dict[str, Any] | None = None,
) -> bytes:
    """Produces deterministic UTF-8 canonical JSON byte representation of audit log record."""
    canonical_dict = {
        "action": str(action),
        "actor_id": str(actor_id),
        "metadata_json": metadata_json or {},
        "organization_id": str(organization_id),
        "previous_hash": str(previous_hash),
        "resource": str(resource),
        "result": str(result),
        "sequence_number": int(sequence_number),
        "timestamp_utc": format_utc_timestamp(timestamp_utc),
        "version": str(version),
    }
    return json.dumps(canonical_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_audit_hash(canonical_bytes: bytes) -> str:
    """Computes SHA-256 hex digest over canonical audit byte sequence."""
    return hashlib.sha256(canonical_bytes).hexdigest()


@dataclasses.dataclass(frozen=True)
class AuditCheckpoint:
    """Trusted external checkpoint representation for tail deletion detection."""

    organization_id: uuid.UUID
    head_sequence_number: int
    head_hash: str


class AuditIntegrityError(Exception):
    """Raised when audit log hash-chain verification detects tamper or sequence anomaly."""

    def __init__(self, error_code: str, sequence_number: int, message: str):
        super().__init__(f"[{error_code}] Seq #{sequence_number}: {message}")
        self.error_code = error_code
        self.sequence_number = sequence_number
        self.message = message


class AuditIntegrityVerifier:
    """Read-only verifier for organization-scoped audit hash chains."""

    @staticmethod
    def verify_chain(
        events: Sequence[Any],
        checkpoint: AuditCheckpoint | None = None,
        expected_start_sequence: int = 1,
    ) -> bool:
        """Verifies organization-scoped audit event sequence for contiguity, hash matching, and link integrity.

        Raises AuditIntegrityError on any detected anomaly.
        """
        if not events:
            if checkpoint is not None:
                raise AuditIntegrityError(
                    error_code="TAIL_DELETED",
                    sequence_number=checkpoint.head_sequence_number,
                    message=f"Audit chain empty but checkpoint expects head seq {checkpoint.head_sequence_number}.",
                )
            return True

        # Ensure events belong to a single organization
        org_ids = {str(getattr(e, "organization_id", None)) for e in events}
        if len(org_ids) > 1:
            raise ValueError(f"Cross-tenant events provided to single tenant verifier: {org_ids}")

        expected_seq = expected_start_sequence
        prev_hash = (
            GENESIS_PREVIOUS_HASH
            if expected_start_sequence == 1
            else getattr(events[0], "previous_hash", GENESIS_PREVIOUS_HASH)
        )

        for event in events:
            seq = getattr(event, "sequence_number", None)
            curr_hash = getattr(event, "current_hash", None)
            event_prev_hash = getattr(event, "previous_hash", None)

            # 1. Sequence gap / contiguity check
            if seq != expected_seq:
                raise AuditIntegrityError(
                    error_code="SEQUENCE_GAP",
                    sequence_number=seq if seq is not None else expected_seq,
                    message=f"Sequence gap detected. Expected seq #{expected_seq}, found seq #{seq}.",
                )

            # 2. Previous hash link check
            if expected_seq == 1:
                if event_prev_hash != GENESIS_PREVIOUS_HASH:
                    raise AuditIntegrityError(
                        error_code="LINK_BROKEN",
                        sequence_number=seq,
                        message=f"Genesis event previous_hash mismatch. Expected '{GENESIS_PREVIOUS_HASH}', found '{event_prev_hash}'.",
                    )
            else:
                if event_prev_hash != prev_hash:
                    raise AuditIntegrityError(
                        error_code="LINK_BROKEN",
                        sequence_number=seq,
                        message=f"Chain link broken. Expected previous_hash '{prev_hash}', found '{event_prev_hash}'.",
                    )

            # 3. Canonical hash digest matching check
            canonical_bytes = canonicalize_audit_entry(
                version="1",
                sequence_number=event.sequence_number,
                previous_hash=event.previous_hash,
                organization_id=event.organization_id,
                actor_id=event.actor_id,
                action=event.action,
                resource=event.resource,
                result=event.result,
                timestamp_utc=event.created_at,
                metadata_json=event.metadata_json,
            )
            recalculated_hash = compute_audit_hash(canonical_bytes)
            if recalculated_hash != curr_hash:
                raise AuditIntegrityError(
                    error_code="RECORD_MODIFIED",
                    sequence_number=seq,
                    message=f"Record content tampered. Recalculated hash '{recalculated_hash}' != stored current_hash '{curr_hash}'.",
                )

            prev_hash = curr_hash
            expected_seq += 1

        # 4. Checkpoint tail deletion check
        if checkpoint is not None:
            last_event = events[-1]
            if (
                last_event.sequence_number != checkpoint.head_sequence_number
                or last_event.current_hash != checkpoint.head_hash
            ):
                raise AuditIntegrityError(
                    error_code="TAIL_DELETED",
                    sequence_number=checkpoint.head_sequence_number,
                    message=(
                        f"Tail deletion detected against trusted checkpoint. "
                        f"DB head seq #{last_event.sequence_number} hash '{last_event.current_hash}' != "
                        f"Checkpoint head seq #{checkpoint.head_sequence_number} hash '{checkpoint.head_hash}'."
                    ),
                )

        return True
