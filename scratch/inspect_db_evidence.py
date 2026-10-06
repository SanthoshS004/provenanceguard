import uuid
import json
from provenanceguard.infrastructure.database.session import DatabaseManager
from provenanceguard.infrastructure.database.models import (
    ArtifactModel,
    VerificationRunModel,
    AuditLogModel,
    ProjectModel,
    OrganizationModel,
)

def inspect_db():
    db_mgr = DatabaseManager()
    org_id = uuid.UUID('00000000-0000-0000-0000-000000000001')
    
    with db_mgr.get_session() as s:
        db_mgr.set_tenant_context(s, org_id)

        print("=== ORGANIZATIONS ===")
        orgs = s.query(OrganizationModel).all()
        for o in orgs:
            print(f"ID: {o.id} | Name: {o.name} | Slug: {o.slug}")

        print("\n=== PROJECTS ===")
        projs = s.query(ProjectModel).filter(ProjectModel.organization_id == org_id).all()
        for p in projs:
            print(f"ID: {p.id} | Org: {p.organization_id} | Name: {p.name}")

        print("\n=== ARTIFACTS ===")
        artifacts = (
            s.query(ArtifactModel)
            .filter(ArtifactModel.organization_id == org_id)
            .order_by(ArtifactModel.created_at.desc())
            .all()
        )
        for a in artifacts:
            print(f"ID: {a.id}")
            print(f"  Org: {a.organization_id}")
            print(f"  Project: {a.project_id}")
            print(f"  Name: {a.name}")
            print(f"  Version: {a.version}")
            print(f"  Media Type: {a.media_type}")
            print(f"  Size: {a.size_bytes} bytes")
            print(f"  Digest (SHA256): {a.digest_sha256}")
            print(f"  Storage Path: {a.storage_path}")
            print(f"  Created: {a.created_at}")

        print("\n=== VERIFICATION RUNS ===")
        runs = (
            s.query(VerificationRunModel)
            .filter(VerificationRunModel.organization_id == org_id)
            .order_by(VerificationRunModel.created_at.desc())
            .all()
        )
        for r in runs:
            print(f"Run ID: {r.id}")
            print(f"  Org: {r.organization_id}")
            print(f"  Project: {r.project_id}")
            print(f"  Production Artifact ID: {r.production_artifact_id}")
            print(f"  Status: {r.status}")
            print(f"  Decision: {r.decision}")
            print(f"  Risk Score: {r.risk_score}")
            print(f"  Attempt Count: {r.attempt_count}")
            print(f"  Created: {r.created_at}")
            print(f"  Completed: {r.completed_at}")

        print("\n=== AUDIT LOGS ===")
        audits = (
            s.query(AuditLogModel)
            .filter(AuditLogModel.organization_id == org_id)
            .order_by(AuditLogModel.sequence_number.desc())
            .limit(10)
            .all()
        )
        for au in audits:
            print(f"ID: {au.id}")
            print(f"  Seq: {au.sequence_number}")
            print(f"  Actor: {au.actor_id}")
            print(f"  Action: {au.action}")
            print(f"  Resource: {au.resource}")
            print(f"  Result: {au.result}")
            print(f"  Prev Hash: {au.previous_hash}")
            print(f"  Curr Hash: {au.current_hash}")
            print(f"  Meta: {au.metadata_json}")
            print(f"  Created: {au.created_at}")

        from provenanceguard.infrastructure.database.models import OutboxEventModel
        print("\n=== OUTBOX EVENTS ===")
        outbox = (
            s.query(OutboxEventModel)
            .filter(OutboxEventModel.organization_id == org_id)
            .order_by(OutboxEventModel.created_at.desc())
            .limit(5)
            .all()
        )
        for e in outbox:
            print(f"Outbox Event ID: {e.id}")
            print(f"  Aggregate Type: {e.aggregate_type}")
            print(f"  Aggregate ID: {e.aggregate_id}")
            print(f"  Event Type: {e.event_type}")
            print(f"  Status: {e.status}")
            print(f"  Dispatched At: {e.dispatched_at}")
            print(f"  Payload: {e.payload_json}")

if __name__ == "__main__":
    inspect_db()
