"""Supplementary Unit Tests for Database ORM Models (SQLite in-memory)."""

import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    Base,
    FindingModel,
    OrganizationModel,
    ProjectModel,
    VerificationRunModel,
)


def test_model_instantiation_and_defaults():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    org = OrganizationModel(name="Acme Corp", slug="acme-corp")
    session.add(org)
    session.commit()

    assert org.id is not None
    assert isinstance(org.id, uuid.UUID)
    assert org.name == "Acme Corp"
    assert org.created_at is not None

    project = ProjectModel(organization_id=org.id, name="Core Engine")
    session.add(project)
    session.commit()

    assert project.id is not None
    assert project.organization_id == org.id

    artifact = ArtifactModel(
        organization_id=org.id,
        project_id=project.id,
        name="app.bin",
        version="1.0.0",
        media_type="application/vnd.elf",
        digest_sha256="a" * 64,
        size_bytes=1024,
        storage_path="/artifacts/app.bin",
    )
    session.add(artifact)
    session.commit()

    assert artifact.id is not None
    assert artifact.size_bytes == 1024

    run = VerificationRunModel(
        organization_id=org.id,
        project_id=project.id,
        production_artifact_id=artifact.id,
        reference_artifact_id=None,
        status="COMPLETED",
        decision="PASS",
        risk_score=0,
    )
    session.add(run)
    session.commit()

    assert run.id is not None
    assert run.decision == "PASS"

    finding = FindingModel(
        verification_run_id=run.id,
        organization_id=org.id,
        severity="INFO",
        category="CLEAN_PASS",
        explanation="No risk factors detected.",
    )
    session.add(finding)
    session.commit()

    assert finding.id is not None
    assert finding.severity == "INFO"
    session.close()
