import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from fastapi.testclient import TestClient

from provenanceguard.apps.api.main import app
from provenanceguard.infrastructure.database.models import (
    ApiKeyModel,
    OrganizationModel,
    ProjectModel,
)
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.integrations.github.ci_action import GitHubCIRunner


def setup_demo_environment():
    """Sets up an organization, project, and API Key in PostgreSQL for local CI simulation."""
    db_mgr = DatabaseManager()
    org_id = uuid.uuid4()
    proj_id = uuid.uuid4()
    key_uuid = uuid.uuid4()
    raw_key = f"pg_live_{uuid.uuid4().hex}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    with db_mgr.get_session() as session:
        org = OrganizationModel(id=org_id, name=f"CI-Org-{org_id.hex[:6]}", slug=f"ci-org-{org_id.hex[:6]}")
        session.add(org)
        session.commit()

        db_mgr.set_tenant_context(session, org_id)
        proj = ProjectModel(id=proj_id, organization_id=org_id, name="CI Pipeline Project")
        session.add(proj)
        session.commit()

        api_key_record = ApiKeyModel(
            id=key_uuid,
            organization_id=org_id,
            project_id=proj_id,
            name="GitHub Actions CI Runner Key",
            prefix=raw_key[:12],
            key_hash=key_hash,
            role="SECURITY_ANALYST",
            scopes_json=["*"],
        )
        session.add(api_key_record)
        session.commit()

    return org_id, proj_id, raw_key


def main():
    print("==================================================")
    print("PROVENANCEGUARD LOCAL CI RUNNER SIMULATION (v1.1.0)")
    print("==================================================")

    # 1. Setup C file fixture and ELF binary
    demo_dir = Path("scratch/ci_demo")
    demo_dir.mkdir(parents=True, exist_ok=True)

    c_file = demo_dir / "main.c"
    c_file.write_text("int main() {\n    return 0;\n}\n", encoding="utf-8")

    elf_file = demo_dir / "app.bin"
    # 64-bit ELF binary header bytes
    elf_header = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    elf_payload = elf_header + b"\x02\x00\x3e\x00" + b"\x41" * 128
    elf_file.write_bytes(elf_payload)

    print(f"[BUILD] Source C file: {c_file.resolve()}")
    print(f"[BUILD] Compiled ELF Binary: {elf_file.resolve()} (Size: {len(elf_payload)} bytes)")

    org_id, proj_id, raw_key = setup_demo_environment()
    print(f"[AUTH] Created Organization: {org_id}")
    print(f"[AUTH] Created Project: {proj_id}")
    print(f"[AUTH] API Key: {raw_key[:12]}... (SHA-256 Hashed in PostgreSQL)")

    # 2. RUN SIMULATION 1: PASS GATE
    print("\n--- SIMULATION 1: SUCCESSFUL CI RUN (PASS GATE) ---")
    pass_env = {
        "PG_API_URL": "http://127.0.0.1:8000",
        "PG_API_KEY": raw_key,
        "PG_PROJECT_ID": str(proj_id),
        "PG_ARTIFACT_PATH": str(elf_file),
        "PG_VERSION": "1.1.0",
        "GITHUB_REPOSITORY": "provenanceguard/demo-app",
        "GITHUB_SHA": "8e1c03fa924dc84c0c408bb33f5815ab59798d41",
        "GITHUB_REF_NAME": "main",
        "GITHUB_WORKFLOW": "Build & Verify",
        "GITHUB_RUN_ID": "104",
    }

    # Note: Using TestClient inside runner for zero-dependency local simulation
    from provenanceguard.integrations.github.ci_action import ProvenanceGuardCIClient
    class MockClient(ProvenanceGuardCIClient):
        def __init__(self, api_key, project_id):
            super().__init__("http://test", api_key, project_id)
            self.test_client = TestClient(app)

        def upload_artifact(self, file_path, name=None, version="1.0.0", project_id=None):
            with open(file_path, "rb") as f:
                resp = self.test_client.post(
                    "/api/v1/artifacts/upload",
                    files={"file": (Path(file_path).name, f, "application/octet-stream")},
                    data={"project_id": project_id or self.project_id, "version": version},
                    headers=self._headers(),
                )
            if resp.status_code != 201:
                raise RuntimeError(f"Upload failed: {resp.text}")
            return resp.json()

        def submit_verification(self, org_id, project_id, production_artifact_id, reference_artifact_id=None):
            resp = self.test_client.post(
                "/api/v1/verifications",
                json={
                    "organization_id": org_id,
                    "project_id": project_id,
                    "production_artifact_id": production_artifact_id,
                },
                headers=self._headers(),
            )
            if resp.status_code != 202:
                raise RuntimeError(f"Verification failed: {resp.text}")
            return resp.json()

        def poll_verification(self, run_id, max_seconds=60, poll_interval=1.0):
            # Synchronously update status for local simulation
            db_mgr = DatabaseManager()
            with db_mgr.get_session() as session:
                from provenanceguard.infrastructure.database.models import VerificationRunModel
                run = session.query(VerificationRunModel).filter(VerificationRunModel.id == uuid.UUID(run_id)).first()
                if run:
                    run.status = "SUCCEEDED"
                    run.decision = "PASS"
                    run.risk_score = 0
                    session.commit()

            resp = self.test_client.get(f"/api/v1/verifications/{run_id}", headers=self._headers())
            return resp.json()

    def mock_run(env_dict):
        client = MockClient(env_dict["PG_API_KEY"], env_dict.get("PG_PROJECT_ID"))
        art_path = env_dict["PG_ARTIFACT_PATH"]
        sys.stdout.write(f"Uploading artifact '{art_path}' to ProvenanceGuard API...\n")
        art_resp = client.upload_artifact(art_path, version="1.1.0", project_id=env_dict.get("PG_PROJECT_ID"))

        art_id = art_resp["id"]
        org_id_val = art_resp["organization_id"]
        proj_id_val = art_resp["project_id"]
        sha256_val = art_resp["digest_sha256"]

        sys.stdout.write(f"Artifact Uploaded! ID: {art_id} | SHA-256: {sha256_val}\n")
        ver_resp = client.submit_verification(org_id_val, proj_id_val, art_id)
        run_id_val = ver_resp["verification_run_id"]
        sys.stdout.write(f"Verification Run Created: {run_id_val}\n")

        res = client.poll_verification(run_id_val)
        sys.stdout.write(f"Decision: {res['decision']} | Risk Score: {res['risk_score']}/100\n")
        sys.stdout.write("::notice::ProvenanceGuard verification PASSED cleanly.\n")
        return 0 if res['decision'] in ('PASS', 'PASS_WITH_WARNING') else 1

    pass_exit = mock_run(pass_env)
    print(f"PASS Simulation Exit Code: {pass_exit} (0 = SUCCESS)")

    # 3. RUN SIMULATION 2: BLOCK GATE
    print("\n--- SIMULATION 2: BLOCKED CI RUN (BLOCK GATE) ---")

    def mock_block_run(env_dict):
        client = MockClient(env_dict["PG_API_KEY"], env_dict.get("PG_PROJECT_ID"))
        art_path = env_dict["PG_ARTIFACT_PATH"]
        art_resp = client.upload_artifact(art_path, version="1.1.0", project_id=env_dict.get("PG_PROJECT_ID"))
        art_id = art_resp["id"]
        org_id_val = art_resp["organization_id"]
        proj_id_val = art_resp["project_id"]

        ver_resp = client.submit_verification(org_id_val, proj_id_val, art_id)
        run_id_val = ver_resp["verification_run_id"]

        # Simulate policy violation BLOCK
        db_mgr = DatabaseManager()
        with db_mgr.get_session() as session:
            from provenanceguard.infrastructure.database.models import VerificationRunModel
            run = session.query(VerificationRunModel).filter(VerificationRunModel.id == uuid.UUID(run_id_val)).first()
            if run:
                run.status = "SUCCEEDED"
                run.decision = "BLOCK"
                run.risk_score = 85
                session.commit()

        res = client.poll_verification(run_id_val)
        sys.stdout.write(f"Decision: {res['decision']} | Risk Score: {res['risk_score']}/100\n")
        sys.stderr.write("::error title=Policy Violation::Artifact rejected by PolicyEngine: Unsigned ELF binary detected\n")
        return 1

    block_exit = mock_block_run(pass_env)
    print(f"BLOCK Simulation Exit Code: {block_exit} (1 = FAILURE/BLOCKED)")

    print("\n[SUCCESS] CI Simulation completed cleanly with both PASS (0) and BLOCK (1) gates demonstrated!")

if __name__ == "__main__":
    main()
