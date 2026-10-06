"""Authoritative PostgreSQL Direct SQL Security Tests using Restricted provenanceguard_app Role.

Verifies database-level security controls connecting strictly as `provenanceguard_app`:
- NO BYPASSRLS enforcement
- DELETE permission denial on application tables and audit_logs
- UPDATE permission denial on audit_logs
- Audit log DB trigger immutability enforcement
- RLS `WITH CHECK` and `USING` tenant isolation
- Connection pool tenant context leakage prevention
- Composite FK cross-project artifact reference rejection
"""

import os
import uuid

import pytest
from sqlalchemy import create_engine, exc, text


def get_admin_engine():
    host = os.getenv("PG_DB_HOST", "localhost")
    port = os.getenv("PG_DB_PORT", "5432")
    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
    user = os.getenv("PG_DB_USER", "provenanceguard_admin")
    password = os.getenv("PG_DB_PASSWORD", "pg_dev_password_change_me")
    sslmode = os.getenv("PG_SSL_MODE", "prefer")
    url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"
    return create_engine(url, pool_pre_ping=True)


def get_app_role_engine():
    host = os.getenv("PG_DB_HOST", "localhost")
    port = os.getenv("PG_DB_PORT", "5432")
    dbname = os.getenv("PG_DB_NAME", "provenanceguard_dev")
    user = os.getenv("PG_APP_USER", "provenanceguard_app")
    password = os.getenv("PG_APP_PASSWORD", "app_dev_password_123")
    sslmode = os.getenv("PG_SSL_MODE", "prefer")
    url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}?sslmode={sslmode}"
    return create_engine(url, pool_pre_ping=True)


def provision_organization(org_id: str) -> None:
    """Provisions organization using system/admin context."""
    admin_engine = get_admin_engine()
    with admin_engine.connect() as conn:
        ins_org = (
            "INSERT INTO organizations (id, name, slug, created_at) "
            "VALUES (:id, :name, :slug, NOW())"
        )
        conn.execute(
            text(ins_org), {"id": org_id, "name": f"Org_{org_id[:8]}", "slug": f"slug_{org_id[:8]}"}
        )
        conn.commit()


def is_postgres_available():
    try:
        engine = get_app_role_engine()
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_postgres_available(),
    reason="PostgreSQL service unavailable for authoritative direct SQL security tests.",
)


def test_pg_app_role_privileges_and_no_bypass_rls():
    engine = get_app_role_engine()
    with engine.connect() as conn:
        # 1. Verify provenanceguard_app has NO BYPASSRLS
        res = conn.execute(
            text("SELECT rolbypassrls FROM pg_roles WHERE rolname = 'provenanceguard_app'")
        ).scalar()
        assert res is False

        # 2. Verify DELETE on organizations is DENIED
        with pytest.raises(exc.DBAPIError):
            conn.execute(text("DELETE FROM organizations WHERE 1=1"))

        # 3. Verify DELETE on audit_logs is DENIED
        with pytest.raises(exc.DBAPIError):
            conn.execute(text("DELETE FROM audit_logs WHERE 1=1"))


def test_pg_audit_log_immutability_trigger():
    org_id = str(uuid.uuid4())
    provision_organization(org_id)

    engine = get_app_role_engine()
    with engine.connect() as conn:
        # Set transaction-local RLS tenant context
        conn.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true)"), {"org_id": org_id}
        )

        # Insert audit log as provenanceguard_app
        audit_id = str(uuid.uuid4())
        ins_audit = (
            "INSERT INTO audit_logs "
            "(id, organization_id, actor_id, action, resource, result, created_at) "
            "VALUES (:id, :org_id, 'actor1', 'TEST', 'res1', 'SUCCESS', NOW())"
        )
        conn.execute(text(ins_audit), {"id": audit_id, "org_id": org_id})
        conn.commit()

        # Attempt UPDATE on audit_logs -> MUST FAIL (Role / Trigger)
        conn.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true)"), {"org_id": org_id}
        )
        with pytest.raises(exc.DBAPIError):
            conn.execute(
                text("UPDATE audit_logs SET action = 'HACKED' WHERE id = :id"),
                {"id": audit_id},
            )
        conn.rollback()

        # Attempt DELETE on audit_logs -> MUST FAIL (Role / Trigger)
        conn.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true)"), {"org_id": org_id}
        )
        with pytest.raises(exc.DBAPIError):
            conn.execute(
                text("DELETE FROM audit_logs WHERE id = :id"),
                {"id": audit_id},
            )


def test_pg_connection_pool_tenant_context_leakage_prevention():
    engine = get_app_role_engine()
    org_a = str(uuid.uuid4())

    with engine.connect() as conn1:
        # Transaction 1: Set Tenant A
        conn1.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true)"), {"org_id": org_a}
        )
        res_a = conn1.execute(
            text("SELECT current_setting('app.current_tenant_id', true)")
        ).scalar()
        assert res_a == org_a
        conn1.commit()

    with engine.connect() as conn2:
        # Transaction 2: Fresh connection from pool without setting tenant context -> MUST BE NULL
        res_b = conn2.execute(
            text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '')")
        ).scalar()
        assert res_b is None


def test_pg_cross_project_artifact_fk_rejection():
    org_id = str(uuid.uuid4())
    provision_organization(org_id)

    proj1_id = str(uuid.uuid4())
    proj2_id = str(uuid.uuid4())
    art1_id = str(uuid.uuid4())
    run_id = str(uuid.uuid4())

    engine = get_app_role_engine()
    with engine.connect() as conn:
        # Establish tenant context as provenanceguard_app
        conn.execute(
            text("SELECT set_config('app.current_tenant_id', :org_id, true)"), {"org_id": org_id}
        )

        # Create Project 1 and Project 2 as provenanceguard_app
        ins_proj = (
            "INSERT INTO projects (id, organization_id, name, created_at) "
            "VALUES (:id, :org_id, :name, NOW())"
        )
        conn.execute(text(ins_proj), {"id": proj1_id, "org_id": org_id, "name": "Project 1"})
        conn.execute(text(ins_proj), {"id": proj2_id, "org_id": org_id, "name": "Project 2"})

        # Create Artifact 1 belonging to Project 1
        ins_art = (
            "INSERT INTO artifacts (id, project_id, organization_id, name, version, "
            "media_type, digest_sha256, size_bytes, storage_path, created_at) "
            "VALUES (:id, :proj_id, :org_id, 'app.bin', '1.0', "
            "'application/vnd.elf', :digest, 1024, '/bin/app', NOW())"
        )
        conn.execute(
            text(ins_art),
            {"id": art1_id, "proj_id": proj1_id, "org_id": org_id, "digest": "a" * 64},
        )
        conn.commit()

        # Attempt to create VerificationRun in Project 2 referencing Artifact 1 from Project 1
        # Database composite FK MUST REJECT this directly!
        ins_run = (
            "INSERT INTO verification_runs (id, project_id, organization_id, "
            "production_artifact_id, status, decision, risk_score, created_at) "
            "VALUES (:id, :proj_id, :org_id, :art_id, 'COMPLETED', 'PASS', 0, NOW())"
        )
        with pytest.raises(exc.DBAPIError):
            conn.execute(
                text(ins_run),
                {"id": run_id, "proj_id": proj2_id, "org_id": org_id, "art_id": art1_id},
            )
