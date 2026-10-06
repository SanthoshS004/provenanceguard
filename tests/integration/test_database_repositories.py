"""Integration Tests for ProvenanceGuard Database Repositories."""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from provenanceguard.infrastructure.database.models import Base
from provenanceguard.infrastructure.database.repositories import (
    ArtifactRepository,
    OrganizationRepository,
    ProjectRepository,
    VerificationRunRepository,
)
from provenanceguard.infrastructure.database.tenant_context import (
    TenantContext,
    TenantSecurityError,
)


def test_repository_crud_and_cross_project_rejection():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org_repo = OrganizationRepository()
    org = org_repo.create_organization(session, name="Cyberdyne", slug="cyberdyne")

    tenant_ctx_p1 = TenantContext(organization_id=org.id, project_id=uuid.uuid4())
    proj_repo = ProjectRepository(tenant_context=tenant_ctx_p1)

    proj1 = proj_repo.create_project(session, name="Skynet Project")
    # Update project_id in context to match created project
    tenant_ctx_p1 = TenantContext(organization_id=org.id, project_id=proj1.id)
    tenant_ctx_p1.validate_project_ownership(session)

    art_repo1 = ArtifactRepository(tenant_context=tenant_ctx_p1)
    art1 = art_repo1.create_artifact(
        session=session,
        name="skynet.elf",
        version="2.0",
        media_type="application/vnd.elf",
        digest_sha256="b" * 64,
        size_bytes=2048,
        storage_path="/bin/skynet.elf",
    )

    # Create second project
    proj2 = proj_repo.create_project(session, name="T-800 Project")
    tenant_ctx_p2 = TenantContext(organization_id=org.id, project_id=proj2.id)

    art_repo2 = ArtifactRepository(tenant_context=tenant_ctx_p2)
    art2 = art_repo2.create_artifact(
        session=session,
        name="t800.elf",
        version="1.0",
        media_type="application/vnd.elf",
        digest_sha256="c" * 64,
        size_bytes=4096,
        storage_path="/bin/t800.elf",
    )

    # VerificationRun in project 1 referencing artifact in project 2 must be rejected
    run_repo1 = VerificationRunRepository(tenant_context=tenant_ctx_p1)
    with pytest.raises(TenantSecurityError):
        run_repo1.create_run(
            session=session,
            production_artifact_id=art2.id,  # art2 belongs to proj2!
            reference_artifact_id=None,
            status="COMPLETED",
            decision="BLOCK",
            risk_score=90,
        )

    # Valid run in project 1 referencing artifact 1 succeeds
    valid_run = run_repo1.create_run(
        session=session,
        production_artifact_id=art1.id,
        reference_artifact_id=None,
        status="COMPLETED",
        decision="PASS",
        risk_score=0,
    )
    assert valid_run.id is not None
    assert valid_run.project_id == proj1.id

    session.close()
