"""Supplementary Unit Tests for Audit Log Repository & Secret Sanitization."""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from provenanceguard.infrastructure.database.models import Base
from provenanceguard.infrastructure.database.repositories import (
    AuditImmutabilityError,
    AuditLogRepository,
)
from provenanceguard.infrastructure.database.tenant_context import TenantContext


def test_audit_log_append_only_and_sanitization():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org_id = uuid.uuid4()
    tenant_ctx = TenantContext(organization_id=org_id)
    audit_repo = AuditLogRepository(tenant_context=tenant_ctx)

    # Test secret sanitization in metadata
    raw_metadata = {
        "user_email": "alice@example.com",
        "api_key": "secret_api_key_12345",
        "nested": {"password": "super_secret_password"},
    }

    entry = audit_repo.log_event(
        session=session,
        actor_id="user_123",
        action="LOGIN",
        resource="portal",
        result="SUCCESS",
        metadata_json=raw_metadata,
    )
    session.commit()

    assert entry.id is not None
    assert entry.metadata_json["user_email"] == "alice@example.com"
    assert entry.metadata_json["api_key"] == "[REDACTED]"
    assert entry.metadata_json["nested"]["password"] == "[REDACTED]"

    # Test update prohibited
    with pytest.raises(AuditImmutabilityError):
        audit_repo.update()

    # Test delete prohibited
    with pytest.raises(AuditImmutabilityError):
        audit_repo.delete()

    session.close()
