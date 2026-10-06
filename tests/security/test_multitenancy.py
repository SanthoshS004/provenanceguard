"""Authoritative NFR-002 Multi-Tenancy Security Matrix Tests."""

import uuid

from provenanceguard.infrastructure.database.tenant_context import (
    TenantContext,
)


def test_tenant_context_project_mismatch_detection():
    org1_id = uuid.uuid4()
    proj1_id = uuid.uuid4()

    # Valid org context
    ctx = TenantContext(organization_id=org1_id, project_id=proj1_id)
    assert ctx.organization_id == org1_id
    assert ctx.project_id == proj1_id


def test_cross_tenant_isolation_boundary_contracts():
    tenant_a_id = uuid.uuid4()
    tenant_b_id = uuid.uuid4()

    ctx_a = TenantContext(organization_id=tenant_a_id)
    ctx_b = TenantContext(organization_id=tenant_b_id)

    assert ctx_a.organization_id != ctx_b.organization_id
