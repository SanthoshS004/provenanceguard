"""FastAPI REST Gateway Application for ProvenanceGuard."""

import os

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from provenanceguard import __version__
from provenanceguard.apps.api.auth import ConfigurationError, get_jwt_public_key
from provenanceguard.apps.api.metrics import (
    PrometheusMetricsMiddleware,
    start_metrics_server,
)
from provenanceguard.apps.api.rate_limiter import (
    PreAuthRateLimitingMiddleware,
    SecurityHeadersMiddleware,
)
from provenanceguard.apps.api.routes_artifacts import router as artifacts_router
from provenanceguard.apps.api.routes_audit import router as audit_router
from provenanceguard.apps.api.routes_auth import router as auth_router
from provenanceguard.apps.api.routes_github import router as github_router
from provenanceguard.apps.api.routes_health import router as health_router
from provenanceguard.apps.api.routes_idp import router as idp_router
from provenanceguard.apps.api.routes_policy import router as policy_router
from provenanceguard.apps.api.routes_projects import router as projects_router
from provenanceguard.apps.api.routes_verifications import router as verifications_router
from provenanceguard.apps.api.routes_webhooks import router as webhooks_router
from provenanceguard.infrastructure.webhooks.webhook_crypto import WebhookCrypto


def check_security_configuration() -> None:
    """Enforces fail-closed security configuration verification on startup."""
    env = os.getenv("PG_ENV", "development").lower()

    # Fail closed if production mode and RS256 public key or webhook key is unconfigured or malformed
    if env == "production":
        get_jwt_public_key()
        WebhookCrypto.get_encryption_key(version=1)


check_security_configuration()

app = FastAPI(
    title="ProvenanceGuard REST API",
    description="Enterprise Software Supply-Chain Verification API",
    version=__version__,
    openapi_url="/api/v1/openapi.json",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
)


@app.on_event("startup")
async def startup_event():
    """Starts dedicated internal Prometheus metrics server and initializes DB schema & seed data."""
    metrics_port = int(os.getenv("PG_API_METRICS_PORT", "9090"))
    try:
        start_metrics_server(port=metrics_port)
    except Exception:
        pass

    # Auto-initialize database tables and seed default tenant
    try:
        import uuid
        from provenanceguard.infrastructure.database.session import Base, DatabaseManager
        from provenanceguard.infrastructure.database.models import OrganizationModel, ProjectModel

        db_mgr = DatabaseManager()
        Base.metadata.create_all(db_mgr.engine)

        with db_mgr.get_session() as session:
            org_id = uuid.UUID('00000000-0000-0000-0000-000000000001')
            proj_id = uuid.UUID('00000000-0000-0000-0000-000000000002')

            existing_org = session.get(OrganizationModel, org_id)
            if not existing_org:
                session.add(OrganizationModel(
                    id=org_id,
                    name="Default Organization",
                    slug="default-org"
                ))
                session.flush()

            existing_proj = session.get(ProjectModel, proj_id)
            if not existing_proj:
                session.add(ProjectModel(
                    id=proj_id,
                    organization_id=org_id,
                    name="Default Project"
                ))
                session.flush()
            session.commit()
    except Exception as e:
        print(f"Startup DB init note: {e}")


# Custom HTTP exception handler for standardized security error responses
@app.exception_handler(ConfigurationError)
async def configuration_error_handler(request: Request, exc: ConfigurationError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "configuration_error", "message": str(exc)},
    )


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    import traceback
    traceback.print_exc()
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "internal_server_error", "message": str(exc)},
    )


# Middlewares
app.add_middleware(PrometheusMetricsMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(PreAuthRateLimitingMiddleware)

# Restrictive CORS configuration - No wildcard origins with credentials
cors_origins_env = os.getenv("PG_CORS_ALLOWED_ORIGINS", "")
if cors_origins_env.strip():
    allowed_origins = [origin.strip() for origin in cors_origins_env.split(",") if origin.strip()]
else:
    allowed_origins = [
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:8080",
        "http://localhost:8080",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Organization-ID",
        "X-Project-ID",
    ],
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(idp_router)
app.include_router(artifacts_router)
app.include_router(verifications_router)
app.include_router(webhooks_router)
app.include_router(projects_router)
app.include_router(audit_router)
app.include_router(policy_router)
app.include_router(github_router)


@app.get("/api/v1/health")
async def health_check():
    return {
        "status": "HEALTHY",
        "service": "provenanceguard-api",
        "version": __version__,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
