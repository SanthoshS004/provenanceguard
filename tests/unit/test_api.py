"""
Unit Tests for FastAPI Endpoints
"""

from fastapi.testclient import TestClient

from provenanceguard.apps.api.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "HEALTHY"
    assert data["service"] == "provenanceguard-api"
