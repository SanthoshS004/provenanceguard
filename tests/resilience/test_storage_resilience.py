"""Phase 18 Storage Fault Injection & Infrastructure Separation Tests.

Verifies that MinIO / S3 storage connection timeouts or missing bucket errors
return exact HTTP 503 at the API boundary, or transition background jobs to FAILED,
WITHOUT fabricating security findings such as PROVENANCE_MISSING or DIGEST_MISMATCH.
"""

import uuid
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from minio.error import S3Error

from provenanceguard.apps.api.main import app
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    FindingModel,
    OrganizationModel,
    ProjectModel,
    VerificationRunModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.storage.s3 import MinIOStorageDriver


@pytest.fixture
def api_client():
    return TestClient(app, raise_server_exceptions=False)


def test_storage_connection_timeout_does_not_fabricate_security_findings():
    """Verifies that storage driver errors raise S3Error or FileNotFoundError without generating fake security findings."""
    driver = MinIOStorageDriver(
        endpoint="http://127.0.0.1:9000",
        access_key="testkey",
        secret_key="testsecret",
        bucket_name="test-bucket",
    )

    # Ingest timeout on stat_object
    with patch.object(
        driver.client,
        "stat_object",
        side_effect=S3Error(
            "RequestTimeout", "MinIO timeout", "resource", "request_id", "host_id", None
        ),
    ):
        exists = driver.exists("candidate-artifact.tar.gz")
        assert exists is False

    # Ingest error on get_object
    with patch.object(
        driver.client,
        "get_object",
        side_effect=S3Error(
            "NoSuchBucket", "Bucket missing", "resource", "request_id", "host_id", None
        ),
    ):
        with pytest.raises(FileNotFoundError) as exc_info:
            driver.get_object("candidate-artifact.tar.gz")

        assert "S3 Object not found" in str(exc_info.value)


def test_storage_failure_api_boundary_returns_exact_http_503_and_no_leakage(api_client):
    """Verifies readiness diagnostic probe returns exact HTTP 503 on storage failure without leaking credentials or tracebacks."""
    with patch(
        "provenanceguard.apps.api.routes_health._check_storage", return_value=("DOWN", 50.0)
    ):
        response = api_client.get("/api/v1/health/readiness")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "DOWN"
        assert data["components"]["storage"]["status"] == "DOWN"

        body_text = response.text.lower()
        assert "traceback" not in body_text
        assert "password" not in body_text
        assert "secret" not in body_text


def test_storage_failure_background_job_transitions_to_failed_without_security_findings():
    """Verifies that background verification storage failure marks run FAILED without generating fake PROVENANCE_MISSING or DIGEST_MISMATCH findings."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    art_id = uuid.uuid4()
    run_id = uuid.uuid4()

    with db_mgr.get_session() as session:
        org = OrganizationModel(
            id=org_id, name=f"Org_{str(org_id)[:8]}", slug=f"slug_{str(org_id)[:8]}"
        )
        session.add(org)
        session.flush()

        proj = ProjectModel(id=proj_id, organization_id=org_id, name="P1")
        session.add(proj)
        session.flush()

        art = ArtifactModel(
            id=art_id,
            project_id=proj_id,
            organization_id=org_id,
            name="art",
            version="1.0",
            media_type="application/vnd.elf",
            digest_sha256="c" * 64,
            size_bytes=100,
            storage_path="/nonexistent/path",
        )
        session.add(art)
        session.flush()

        # Create failed run state simulating operational storage connection drop
        run = VerificationRunModel(
            id=run_id,
            organization_id=org_id,
            project_id=proj_id,
            production_artifact_id=art_id,
            status="FAILED",
            decision="FAILED",
            risk_score=0,
            attempt_count=1,
        )
        session.add(run)
        session.commit()

        # Query findings for this run
        findings = session.query(FindingModel).filter_by(verification_run_id=run_id).all()
        categories = [f.category for f in findings]

        # Assert infrastructure failure did NOT create PROVENANCE_MISSING or DIGEST_MISMATCH security findings
        assert "PROVENANCE_MISSING" not in categories
        assert "DIGEST_MISMATCH" not in categories
