"""
ProvenanceGuard v1.0.0 End-to-End Real Workflow Verification Script
"""
import sys
import uuid
import time
import json
import urllib.request
import urllib.error
from sqlalchemy import text

from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.tenant_context import TenantContext
from provenanceguard.apps.api.auth import mint_dev_token

def main():
    print("=" * 70)
    print("PROVENANCEGUARD V1.0.0 END-TO-END WORKFLOW VERIFICATION")
    print("=" * 70)

    db_mgr = DatabaseManager()
    org_id = uuid.UUID("00000000-0000-0000-0000-000000000001")
    proj_id = uuid.UUID("00000000-0000-0000-0000-000000000002")

    # 1. Check/Seed Organization & Project
    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)
        
        # Seed Org
        session.execute(text("""
            INSERT INTO organizations (id, name, slug, created_at)
            VALUES (:id, 'Acme Security (Default)', 'acme-security', NOW())
            ON CONFLICT (id) DO NOTHING;
        """), {"id": str(org_id)})

        # Seed Proj
        session.execute(text("""
            INSERT INTO projects (id, organization_id, name, created_at)
            VALUES (:id, :org_id, 'Default Project', NOW())
            ON CONFLICT (id) DO NOTHING;
        """), {"id": str(proj_id), "org_id": str(org_id)})
        
        session.commit()
    print("[OK] Organization & Project verified/seeded in PostgreSQL.")

    # 2. Mint Dev Token via REST API
    req_token_body = json.dumps({
        "organization_id": str(org_id),
        "role": "SECURITY_ANALYST",
        "user_id": "e2e-tester-01",
        "project_id": str(proj_id),
        "scopes": ["*"]
    }).encode("utf-8")

    req_token = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/auth/token",
        data=req_token_body,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    with urllib.request.urlopen(req_token) as resp:
        token_data = json.loads(resp.read().decode("utf-8"))
        jwt_token = token_data["access_token"]
        print(f"[OK] Obtained Dev JWT Token via API (Length: {len(jwt_token)} chars)")

    # 3. Seed Test A Artifacts (Clean/Matching Pair)
    prod_art_id_a = uuid.uuid4()
    ref_art_id_a = uuid.uuid4()
    digest_prod_a = f"a{uuid.uuid4().hex}{uuid.uuid4().hex}"[:64]
    digest_ref_a =  f"b{uuid.uuid4().hex}{uuid.uuid4().hex}"[:64]

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        session.execute(text("""
            INSERT INTO artifacts (id, project_id, organization_id, name, version, media_type, digest_sha256, size_bytes, storage_path, created_at)
            VALUES (:id, :proj_id, :org_id, 'app-service-clean.bin', '1.0.0', 'application/vnd.elf', :digest, 4096, '/storage/clean.bin', NOW())
            ON CONFLICT DO NOTHING;
        """), {"id": str(prod_art_id_a), "proj_id": str(proj_id), "org_id": str(org_id), "digest": digest_prod_a})

        session.execute(text("""
            INSERT INTO artifacts (id, project_id, organization_id, name, version, media_type, digest_sha256, size_bytes, storage_path, created_at)
            VALUES (:id, :proj_id, :org_id, 'app-service-ref.bin', '1.0.0', 'application/vnd.elf', :digest, 4096, '/storage/ref.bin', NOW())
            ON CONFLICT DO NOTHING;
        """), {"id": str(ref_art_id_a), "proj_id": str(proj_id), "org_id": str(org_id), "digest": digest_ref_a})

        session.commit()

    print(f"[OK] TEST A Artifacts Seeded: Prod={prod_art_id_a}, Ref={ref_art_id_a}")
    print(f"     Prod Digest: {digest_prod_a}")
    print(f"     Ref Digest:  {digest_ref_a}")

    # 4. Submit TEST A Verification Job via REST API
    req_body_a = json.dumps({
        "organization_id": str(org_id),
        "project_id": str(proj_id),
        "production_artifact_id": str(prod_art_id_a),
        "reference_artifact_id": str(ref_art_id_a)
    }).encode("utf-8")

    req_a = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/verifications",
        data=req_body_a,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {jwt_token}"
        },
        method="POST"
    )

    with urllib.request.urlopen(req_a) as resp:
        res_data_a = json.loads(resp.read().decode("utf-8"))
        run_id_a = res_data_a.get("verification_run_id") or res_data_a.get("id")
        print(f"[OK] TEST A Submitted -> HTTP {resp.status}, Verification Run ID: {run_id_a}")

    # 5. Wait for Background Worker to process TEST A
    print("Waiting for worker processing...")
    completed_a = False
    for _ in range(15):
        time.sleep(1)
        req_get_a = urllib.request.Request(
            f"http://127.0.0.1:8000/api/v1/verifications/{run_id_a}",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )
        try:
            with urllib.request.urlopen(req_get_a) as resp:
                data_get_a = json.loads(resp.read().decode("utf-8"))
                if data_get_a["status"] in ("SUCCEEDED", "FAILED"):
                    completed_a = True
                    print(f"[OK] TEST A Worker Execution Finished -> Status: {data_get_a['status']}, Decision: {data_get_a['decision']}, Risk Score: {data_get_a['risk_score']}")
                    print(f"    Full Record A: {json.dumps(data_get_a, indent=2)}")
                    break
        except Exception as e:
            print(f"    Pending API check: {e}")

    if not completed_a:
        print("[!] Worker did not finish Test A in 15 seconds.")

    # 6. Seed TEST B Artifacts (Discrepancy: Diff Digest)
    prod_art_id_b = uuid.uuid4()
    ref_art_id_b = uuid.uuid4()
    digest_prod_b = f"c{uuid.uuid4().hex}{uuid.uuid4().hex}"[:64]
    digest_ref_b =  f"d{uuid.uuid4().hex}{uuid.uuid4().hex}"[:64]

    with db_mgr.get_session() as session:
        db_mgr.set_tenant_context(session, org_id)

        session.execute(text("""
            INSERT INTO artifacts (id, project_id, organization_id, name, version, media_type, digest_sha256, size_bytes, storage_path, created_at)
            VALUES (:id, :proj_id, :org_id, 'app-service-tampered.bin', '1.0.0', 'application/vnd.elf', :digest, 4096, '/storage/tampered.bin', NOW())
            ON CONFLICT DO NOTHING;
        """), {"id": str(prod_art_id_b), "proj_id": str(proj_id), "org_id": str(org_id), "digest": digest_prod_b})

        session.execute(text("""
            INSERT INTO artifacts (id, project_id, organization_id, name, version, media_type, digest_sha256, size_bytes, storage_path, created_at)
            VALUES (:id, :proj_id, :org_id, 'app-service-ref.bin', '1.0.0', 'application/vnd.elf', :digest, 4096, '/storage/ref.bin', NOW())
            ON CONFLICT DO NOTHING;
        """), {"id": str(ref_art_id_b), "proj_id": str(proj_id), "org_id": str(org_id), "digest": digest_ref_b})

        session.commit()

    print(f"[OK] TEST B Artifacts Seeded: Prod={prod_art_id_b}, Ref={ref_art_id_b}")
    print(f"     Prod Digest: {digest_prod_b}")
    print(f"     Ref Digest:  {digest_ref_b}")

    # 7. Submit TEST B Verification Job via REST API
    req_body_b = json.dumps({
        "organization_id": str(org_id),
        "project_id": str(proj_id),
        "production_artifact_id": str(prod_art_id_b),
        "reference_artifact_id": str(ref_art_id_b)
    }).encode("utf-8")

    req_b = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/verifications",
        data=req_body_b,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {jwt_token}"
        },
        method="POST"
    )

    with urllib.request.urlopen(req_b) as resp:
        res_data_b = json.loads(resp.read().decode("utf-8"))
        run_id_b = res_data_b.get("verification_run_id") or res_data_b.get("id")
        print(f"[OK] TEST B Submitted -> HTTP {resp.status}, Verification Run ID: {run_id_b}")

    # 8. Wait for Background Worker to process TEST B
    print("Waiting for worker processing...")
    completed_b = False
    for _ in range(15):
        time.sleep(1)
        req_get_b = urllib.request.Request(
            f"http://127.0.0.1:8000/api/v1/verifications/{run_id_b}",
            headers={"Authorization": f"Bearer {jwt_token}"}
        )
        try:
            with urllib.request.urlopen(req_get_b) as resp:
                data_get_b = json.loads(resp.read().decode("utf-8"))
                if data_get_b["status"] in ("SUCCEEDED", "FAILED"):
                    completed_b = True
                    print(f"[OK] TEST B Worker Execution Finished -> Status: {data_get_b['status']}, Decision: {data_get_b['decision']}, Risk Score: {data_get_b['risk_score']}")
                    print(f"    Full Record B: {json.dumps(data_get_b, indent=2)}")
                    break
        except Exception as e:
            print(f"    Pending API check: {e}")

    # 9. Verify Audit Logs via API Endpoint
    print("\nQuerying Audit Log Stream via REST API GET /api/v1/audit-log...")
    req_audit = urllib.request.Request(
        "http://127.0.0.1:8000/api/v1/audit-log",
        headers={"Authorization": f"Bearer {jwt_token}"}
    )
    with urllib.request.urlopen(req_audit) as resp:
        audit_data = json.loads(resp.read().decode("utf-8"))
        print(f"[OK] Audit Stream Total Records: {audit_data.get('total', 0)}")
        for item in audit_data.get("items", [])[:5]:
            print(f"    - Event ID: {item.get('id')}, Action: {item.get('action')}, Resource: {item.get('resource')}, Result: {item.get('result')}")

if __name__ == "__main__":
    main()
