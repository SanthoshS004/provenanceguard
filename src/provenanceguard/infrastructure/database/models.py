"""SQLAlchemy 2.0 ORM Declarative Models for ProvenanceGuard.

Defines all relational entities, composite unique & foreign key constraints,
CHECK constraints, and timezone-aware UTC timestamps.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    BIGINT,
    CHAR,
    INT,
    JSON,
    TEXT,
    VARCHAR,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    LargeBinary,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.types import TypeDecorator
from sqlalchemy.orm import Mapped, mapped_column, relationship

from provenanceguard.infrastructure.database.session import Base


def utc_now() -> datetime:
    """Returns current UTC timestamp with timezone."""
    return datetime.now(timezone.utc)


from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID as PG_UUID

class GUID(TypeDecorator):
    """Platform-independent GUID type.
    Uses PostgreSQL's UUID type when connected to PostgreSQL, otherwise CHAR(36) for SQLite.
    """
    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_GUID())
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))



class OrganizationModel(Base):
    __tablename__ = "organizations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(VARCHAR(255), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(VARCHAR(100), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    projects = relationship(
        "ProjectModel", back_populates="organization", cascade="all, delete-orphan"
    )
    audit_logs = relationship("AuditLogModel", back_populates="organization")


class ProjectModel(Base):
    __tablename__ = "projects"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_projects_id_organization_id"),
        UniqueConstraint("organization_id", "name", name="uq_projects_organization_id_name"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    organization = relationship("OrganizationModel", back_populates="projects")
    artifacts = relationship("ArtifactModel", back_populates="project")
    verification_runs = relationship("VerificationRunModel", back_populates="project")


class RepositoryModel(Base):
    __tablename__ = "repositories"
    __table_args__ = (
        ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_repositories_project_org",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    remote_url: Mapped[str] = mapped_column(VARCHAR(1024), nullable=False)
    default_branch: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class BuildModel(Base):
    __tablename__ = "builds"
    __table_args__ = (
        ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_builds_project_org",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    builder_image: Mapped[str] = mapped_column(VARCHAR(1024), nullable=False)
    commit_sha: Mapped[str] = mapped_column(VARCHAR(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ArtifactModel(Base):
    __tablename__ = "artifacts"
    __table_args__ = (
        UniqueConstraint("id", "project_id", name="uq_artifacts_id_project_id"),
        UniqueConstraint("project_id", "digest_sha256", name="uq_artifacts_project_digest"),
        ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_artifacts_project_org",
        ),
        CheckConstraint("size_bytes >= 0", name="ck_artifacts_size_non_negative"),
        CheckConstraint("length(digest_sha256) = 64", name="ck_artifacts_digest_sha256_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    version: Mapped[str] = mapped_column(VARCHAR(100), nullable=False)
    media_type: Mapped[str] = mapped_column(VARCHAR(100), nullable=False)
    digest_sha256: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BIGINT, nullable=False)
    storage_path: Mapped[str] = mapped_column(VARCHAR(1024), nullable=False)
    git_repository: Mapped[str | None] = mapped_column(VARCHAR(255), nullable=True)
    git_branch: Mapped[str | None] = mapped_column(VARCHAR(255), nullable=True)
    git_commit_sha: Mapped[str | None] = mapped_column(VARCHAR(128), nullable=True)
    git_workflow_run_id: Mapped[str | None] = mapped_column(VARCHAR(128), nullable=True)
    git_workflow_name: Mapped[str | None] = mapped_column(VARCHAR(255), nullable=True)
    git_build_number: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    artifact_type: Mapped[str] = mapped_column(VARCHAR(50), nullable=False, default="BUILD_ARTIFACT")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    project = relationship("ProjectModel", back_populates="artifacts")


class GitHubIntegrationModel(Base):
    __tablename__ = "github_integrations"
    __table_args__ = (
        UniqueConstraint("organization_id", "project_id", name="uq_github_integrations_org_project"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("projects.id", ondelete="RESTRICT"),
        nullable=False,
    )
    repository: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    default_branch: Mapped[str] = mapped_column(VARCHAR(255), nullable=False, default="main")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    last_collected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    organization = relationship("OrganizationModel")
    project = relationship("ProjectModel")



class VerificationRunModel(Base):
    __tablename__ = "verification_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["production_artifact_id", "project_id"],
            ["artifacts.id", "artifacts.project_id"],
            ondelete="RESTRICT",
            name="fk_verification_runs_production_artifact_project",
        ),
        ForeignKeyConstraint(
            ["reference_artifact_id", "project_id"],
            ["artifacts.id", "artifacts.project_id"],
            ondelete="RESTRICT",
            name="fk_verification_runs_reference_artifact_project",
        ),
        ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_verification_runs_project_org",
        ),
        UniqueConstraint("id", "project_id", name="uq_verification_runs_id_project_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    project_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    production_artifact_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    reference_artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(), nullable=True
    )
    status: Mapped[str] = mapped_column(VARCHAR(50), nullable=False)
    decision: Mapped[str] = mapped_column(VARCHAR(50), nullable=False)
    risk_score: Mapped[int] = mapped_column(INT, nullable=False)
    attempt_count: Mapped[int] = mapped_column(INT, nullable=False, default=1)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    project = relationship("ProjectModel", back_populates="verification_runs")
    findings = relationship(
        "FindingModel", back_populates="verification_run", cascade="all, delete-orphan"
    )


class OutboxEventModel(Base):
    __tablename__ = "outbox_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="RESTRICT",
            name="fk_outbox_events_organization",
        ),
        ForeignKeyConstraint(
            ["aggregate_id", "project_id"],
            ["verification_runs.id", "verification_runs.project_id"],
            ondelete="RESTRICT",
            name="fk_outbox_events_verification_run_project",
        ),
        ForeignKeyConstraint(
            ["project_id", "organization_id"],
            ["projects.id", "projects.organization_id"],
            ondelete="RESTRICT",
            name="fk_outbox_events_project_org",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    aggregate_type: Mapped[str] = mapped_column(VARCHAR(50), nullable=False)
    aggregate_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    event_type: Mapped[str] = mapped_column(VARCHAR(100), nullable=False)
    payload_json: Mapped[dict] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )
    status: Mapped[str] = mapped_column(VARCHAR(20), nullable=False, default="PENDING")
    attempts: Mapped[int] = mapped_column(INT, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class FindingModel(Base):
    __tablename__ = "findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["verification_run_id"],
            ["verification_runs.id"],
            ondelete="RESTRICT",
            name="fk_findings_verification_run",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    verification_run_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    severity: Mapped[str] = mapped_column(VARCHAR(20), nullable=False)
    category: Mapped[str] = mapped_column(VARCHAR(100), nullable=False)
    explanation: Mapped[str] = mapped_column(TEXT, nullable=False)
    remediation: Mapped[str | None] = mapped_column(TEXT, nullable=True)
    details_json: Mapped[dict | None] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    verification_run = relationship("VerificationRunModel", back_populates="findings")


class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="RESTRICT",
            name="fk_audit_logs_organization",
        ),
        UniqueConstraint("organization_id", "sequence_number", name="uq_audit_logs_org_sequence"),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    sequence_number: Mapped[int] = mapped_column(BIGINT, nullable=False, default=1)
    actor_id: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    action: Mapped[str] = mapped_column(VARCHAR(100), nullable=False)
    resource: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    result: Mapped[str] = mapped_column(VARCHAR(50), nullable=False)
    previous_hash: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False,
        default="0000000000000000000000000000000000000000000000000000000000000000",
    )
    current_hash: Mapped[str] = mapped_column(
        CHAR(64),
        nullable=False,
        default="0000000000000000000000000000000000000000000000000000000000000000",
    )
    metadata_json: Mapped[dict | None] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    organization = relationship("OrganizationModel", back_populates="audit_logs")


class ApiKeyModel(Base):
    __tablename__ = "api_keys"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_api_keys_org_name"),)

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        GUID(),
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=True,
    )
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    prefix: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    key_hash: Mapped[str] = mapped_column(CHAR(64), unique=True, nullable=False)
    role: Mapped[str] = mapped_column(VARCHAR(50), nullable=False)
    scopes_json: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False, default=list
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    organization = relationship("OrganizationModel")
    project = relationship("ProjectModel")


class WebhookSubscriptionModel(Base):
    __tablename__ = "webhook_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    target_url: Mapped[str] = mapped_column(VARCHAR(1024), nullable=False)
    secret_key_version: Mapped[int] = mapped_column(INT, nullable=False, default=1)
    secret_nonce: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    encrypted_secret: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    secret_fingerprint: Mapped[str] = mapped_column(CHAR(64), nullable=False)
    events_json: Mapped[list] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    organization = relationship("OrganizationModel")
    deliveries = relationship(
        "WebhookDeliveryModel", back_populates="subscription", cascade="all, delete-orphan"
    )


class WebhookDeliveryModel(Base):
    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        UniqueConstraint("subscription_id", "event_id", name="uq_webhook_deliveries_sub_event"),
        CheckConstraint(
            "attempt_count >= 0 AND attempt_count <= 5", name="ck_webhook_deliveries_attempt_count"
        ),
        CheckConstraint(
            "status IN ('PENDING', 'DISPATCHING', 'DELIVERED', 'RETRY_PENDING', 'FAILED', 'DISABLED')",
            name="ck_webhook_deliveries_status",
        ),
        CheckConstraint(
            "event_type IN ('VERIFICATION_COMPLETED', 'FINDING_DETECTED', 'API_KEY_REVOKED')",
            name="ck_webhook_deliveries_event_type",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    subscription_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("webhook_subscriptions.id", ondelete="CASCADE"),
        nullable=False,
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    event_id: Mapped[uuid.UUID] = mapped_column(GUID(), nullable=False)
    event_type: Mapped[str] = mapped_column(VARCHAR(100), nullable=False)
    status: Mapped[str] = mapped_column(VARCHAR(20), nullable=False, default="PENDING")
    attempt_count: Mapped[int] = mapped_column(INT, nullable=False, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_status_code: Mapped[int | None] = mapped_column(INT, nullable=True)
    error_summary: Mapped[str | None] = mapped_column(VARCHAR(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    subscription = relationship("WebhookSubscriptionModel", back_populates="deliveries")
    organization = relationship("OrganizationModel")


class IdPConfigModel(Base):
    __tablename__ = "idp_configurations"

    id: Mapped[uuid.UUID] = mapped_column(GUID(), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        GUID(),
        ForeignKey("organizations.id", ondelete="RESTRICT"),
        nullable=False,
    )
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    issuer: Mapped[str] = mapped_column(VARCHAR(1024), nullable=False)
    client_id: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    jwks_uri: Mapped[str] = mapped_column(VARCHAR(1024), nullable=False)
    subject_claim: Mapped[str] = mapped_column(VARCHAR(50), nullable=False, default="sub")
    group_claim: Mapped[str] = mapped_column(VARCHAR(50), nullable=False, default="groups")
    group_role_map_json: Mapped[dict] = mapped_column(
        JSONB().with_variant(JSON(), "sqlite"), nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    organization = relationship("OrganizationModel")
