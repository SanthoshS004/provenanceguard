"""Security tests for Content-Security-Policy (CSP) headers across environments and endpoints."""

from fastapi.testclient import TestClient

from provenanceguard.apps.api.main import app


def test_swagger_docs_csp_when_pg_env_unset(monkeypatch):
    """Verifies that GET /api/v1/docs serves scoped development CSP when PG_ENV is completely unset (defaulting to dev mode)."""
    monkeypatch.delenv("PG_ENV", raising=False)
    client = TestClient(app)

    response = client.get("/api/v1/docs")
    assert response.status_code == 200

    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "https://cdn.jsdelivr.net" in csp
    assert "'unsafe-inline'" in csp
    assert "https://fastapi.tiangolo.com" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_swagger_docs_csp_in_development(monkeypatch):
    """Verifies that GET /api/v1/docs serves a scoped development CSP when PG_ENV is explicitly 'development'."""
    monkeypatch.setenv("PG_ENV", "development")
    client = TestClient(app)

    response = client.get("/api/v1/docs")
    assert response.status_code == 200

    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "https://cdn.jsdelivr.net" in csp
    assert "'unsafe-inline'" in csp
    assert "https://fastapi.tiangolo.com" in csp
    assert "connect-src 'self'" in csp
    assert "frame-ancestors 'none'" in csp


def test_redoc_csp_in_development(monkeypatch):
    """Verifies that GET /api/v1/redoc serves a scoped development CSP allowing ReDoc assets."""
    monkeypatch.setenv("PG_ENV", "development")
    client = TestClient(app)

    response = client.get("/api/v1/redoc")
    assert response.status_code == 200

    csp = response.headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "https://cdn.jsdelivr.net" in csp


def test_openapi_json_remains_valid_and_strict_csp(monkeypatch):
    """Verifies that GET /api/v1/openapi.json returns 200, valid OpenAPI 3 schema, and strict CSP when PG_ENV is unset."""
    monkeypatch.delenv("PG_ENV", raising=False)
    client = TestClient(app)

    response = client.get("/api/v1/openapi.json")
    assert response.status_code == 200

    data = response.json()
    assert "openapi" in data
    assert data["openapi"].startswith("3.")

    csp = response.headers.get("Content-Security-Policy", "")
    assert csp == "default-src 'none'; frame-ancestors 'none'"


def test_api_endpoint_csp_remains_strict_in_development(monkeypatch):
    """Verifies that standard API endpoints (/api/v1/health) retain strict default-src 'none' in development / unset PG_ENV."""
    monkeypatch.delenv("PG_ENV", raising=False)
    client = TestClient(app)

    response = client.get("/api/v1/health")
    assert response.status_code == 200

    csp = response.headers.get("Content-Security-Policy", "")
    assert csp == "default-src 'none'; frame-ancestors 'none'"


def test_swagger_docs_csp_remains_strict_in_production(monkeypatch):
    """Verifies that GET /api/v1/docs retains fail-closed default-src 'none' CSP in production mode."""
    monkeypatch.setenv("PG_ENV", "production")
    client = TestClient(app)

    response = client.get("/api/v1/docs")
    assert response.status_code == 200

    csp = response.headers.get("Content-Security-Policy", "")
    assert csp == "default-src 'none'; frame-ancestors 'none'"
