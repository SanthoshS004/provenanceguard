"""Unit & Security Integration Tests for REST API Artifact Upload Endpoint (routes_artifacts.py)."""

import io
import struct
import uuid
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from provenanceguard.apps.api.auth import mint_dev_token
from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.rbac import Role
from provenanceguard.infrastructure.database.models import ArtifactModel, utc_now

client = TestClient(app)


def make_test_elf_bytes() -> bytes:
    """Helper creating a minimal valid 64-bit ELF binary."""
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 120, 0, 64, 56, 1, 64, 2, 1)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 256, 256, 4096)
    shdr0 = b"\x00" * 64
    shdr1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 248, 11, 0, 0, 1, 0)
    shstrtab = b"\x00.shstrtab\x00"
    return ident + header + phdr + shdr0 + shdr1 + shstrtab


def test_upload_artifact_unauthorized():
    """Request without token returns 401 Unauthorized."""
    resp = client.post(
        "/api/v1/artifacts/upload",
        files={"file": ("test.bin", io.BytesIO(b"data"), "application/octet-stream")},
    )
    assert resp.status_code == 401


def test_upload_artifact_success():
    """Authenticated user uploads an artifact; server computes SHA-256 and persists record."""
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-sec-analyst",
        organization_id=org_id,
        role=Role.SECURITY_ANALYST,
        project_id=proj_id,
    )

    elf_payload = make_test_elf_bytes()
    artifact_id = uuid.uuid4()

    dummy_artifact = ArtifactModel(
        id=artifact_id,
        organization_id=org_id,
        project_id=proj_id,
        name="test-binary.bin",
        version="1.0.0",
        media_type="application/vnd.elf",
        digest_sha256="a" * 64,
        size_bytes=len(elf_payload),
        storage_path=f"s3://provenanceguard-artifacts/{org_id}/{proj_id}/artifacts/{'a'*64}",
        created_at=utc_now(),
    )

    with patch("provenanceguard.apps.api.routes_artifacts.ArtifactRepository") as MockArtifactRepoClass, \
         patch("provenanceguard.apps.api.routes_artifacts.AuditLogRepository"):
        mock_repo_inst = MagicMock()
        mock_repo_inst.get_by_digest.return_value = None
        mock_repo_inst.create_artifact.return_value = dummy_artifact
        MockArtifactRepoClass.return_value = mock_repo_inst

        resp = client.post(
            "/api/v1/artifacts/upload",
            headers={"Authorization": f"Bearer {token_str}"},
            files={"file": ("test-binary.bin", io.BytesIO(elf_payload), "application/octet-stream")},
            data={"project_id": str(proj_id), "version": "1.0.0"},
        )

        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] == str(artifact_id)
        assert data["organization_id"] == str(org_id)
        assert data["project_id"] == str(proj_id)
        assert data["name"] == "test-binary.bin"
        assert data["media_type"] == "application/vnd.elf"


def test_list_artifacts_authenticated():
    """Authenticated user lists tenant artifacts."""
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    token_str = mint_dev_token(
        user_id="test-sec-analyst",
        organization_id=org_id,
        role=Role.SECURITY_ANALYST,
    )

    dummy_artifact = ArtifactModel(
        id=uuid.uuid4(),
        organization_id=org_id,
        project_id=proj_id,
        name="app-service.bin",
        version="1.0.0",
        media_type="application/vnd.elf",
        digest_sha256="b" * 64,
        size_bytes=4096,
        storage_path="/storage/app-service.bin",
        created_at=utc_now(),
    )

    with patch("provenanceguard.apps.api.routes_artifacts.DatabaseManager") as MockDBManager:
        mock_db = MagicMock()
        mock_session = MagicMock()
        mock_session.scalars.return_value.all.return_value = [dummy_artifact]
        mock_db.get_session.return_value.__enter__.return_value = mock_session
        MockDBManager.return_value = mock_db

        resp = client.get(
            "/api/v1/artifacts",
            headers={"Authorization": f"Bearer {token_str}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["name"] == "app-service.bin"
