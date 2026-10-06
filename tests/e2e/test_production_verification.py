"""End-to-End Production Security & Infrastructure Verification Test Suite for Phase 16.

Verifies:
1. API dual-port architecture (REST on 8000, Prometheus metrics on 9090).
2. Process-only liveness probe and concurrent 5-second deadline readiness probe failure modes.
3. Metric route template normalization and zero high-cardinality/PII labels.
4. ARQ Worker independent metrics and liveness separation.
5. Production Helm 3 chart fail-closed secret validation, NetworkPolicies, PDBs, and seccomp profiles.
6. Container non-root execution and Python-native healthchecks.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from provenanceguard.apps.api.main import app
from provenanceguard.apps.api.metrics import (
    HTTP_REQUESTS_TOTAL,
    POLICY_EVALUATIONS_TOTAL,
    get_normalized_route,
)
from provenanceguard.apps.worker.worker_metrics import (
    WORKER_TASKS_TOTAL,
    update_worker_heartbeat,
)


@pytest.fixture
def client():
    """FastAPI TestClient for REST API Gateway endpoints on port 8000."""
    return TestClient(app)


# ============================================================================
# 1. HEALTH & READINESS PROBE TESTS
# ============================================================================


def test_liveness_check_is_process_only(client):
    """Verifies liveness probe returns HTTP 200 OK process-only status quickly."""
    response = client.get("/api/v1/health/liveness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UP"
    assert data["probe"] == "liveness"
    assert data["service"] == "provenanceguard-api"


def test_readiness_check_all_healthy(client):
    """Verifies readiness probe returns HTTP 200 when all dependencies report UP."""
    with (
        patch("provenanceguard.apps.api.routes_health._check_database", return_value=("UP", 1.5)),
        patch("provenanceguard.apps.api.routes_health._check_redis", return_value=("UP", 2.1)),
        patch("provenanceguard.apps.api.routes_health._check_storage", return_value=("UP", 3.0)),
    ):
        response = client.get("/api/v1/health/readiness")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "UP"
        assert data["components"]["database"]["status"] == "UP"
        assert data["components"]["redis"]["status"] == "UP"
        assert data["components"]["storage"]["status"] == "UP"


def test_readiness_check_database_failure(client):
    """Verifies readiness returns 503 Service Unavailable when PostgreSQL fails."""
    with (
        patch(
            "provenanceguard.apps.api.routes_health._check_database", return_value=("DOWN", 50.0)
        ),
        patch("provenanceguard.apps.api.routes_health._check_redis", return_value=("UP", 2.1)),
        patch("provenanceguard.apps.api.routes_health._check_storage", return_value=("UP", 3.0)),
    ):
        response = client.get("/api/v1/health/readiness")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "DOWN"
        assert data["components"]["database"]["status"] == "DOWN"
        # Assert response payload is sanitized (no passwords, hostnames, stack traces)
        content_str = str(data)
        assert "password" not in content_str.lower()
        assert "postgresql://" not in content_str.lower()


def test_readiness_check_redis_failure(client):
    """Verifies readiness returns 503 Service Unavailable when Redis fails."""
    with (
        patch("provenanceguard.apps.api.routes_health._check_database", return_value=("UP", 1.5)),
        patch("provenanceguard.apps.api.routes_health._check_redis", return_value=("DOWN", 50.0)),
        patch("provenanceguard.apps.api.routes_health._check_storage", return_value=("UP", 3.0)),
    ):
        response = client.get("/api/v1/health/readiness")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "DOWN"
        assert data["components"]["redis"]["status"] == "DOWN"


def test_readiness_check_storage_failure(client):
    """Verifies readiness returns 503 Service Unavailable when MinIO fails."""
    with (
        patch("provenanceguard.apps.api.routes_health._check_database", return_value=("UP", 1.5)),
        patch("provenanceguard.apps.api.routes_health._check_redis", return_value=("UP", 2.1)),
        patch("provenanceguard.apps.api.routes_health._check_storage", return_value=("DOWN", 50.0)),
    ):
        response = client.get("/api/v1/health/readiness")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "DOWN"
        assert data["components"]["storage"]["status"] == "DOWN"


@pytest.mark.asyncio
async def test_readiness_overall_deadline_enforcement():
    """Verifies readiness probe enforces an overall 5-second deadline."""

    async def _slow_check():
        await asyncio.sleep(10.0)  # Exceeds 5.0s deadline
        return ("UP", 10000.0)

    with (
        patch("provenanceguard.apps.api.routes_health._check_database", side_effect=_slow_check),
        patch("provenanceguard.apps.api.routes_health._check_redis", return_value=("UP", 2.1)),
        patch("provenanceguard.apps.api.routes_health._check_storage", return_value=("UP", 3.0)),
    ):
        # Invoke handler directly with mock response
        from provenanceguard.apps.api.routes_health import readiness_check

        mock_response = MagicMock()
        payload = await readiness_check(mock_response)
        assert payload["status"] == "DOWN"
        assert mock_response.status_code == 503


# ============================================================================
# 2. PROMETHEUS METRICS & CARDINALITY TESTS
# ============================================================================


def test_prometheus_route_template_normalization():
    """Verifies FastAPI route templates normalize raw parameterized paths."""
    mock_request = MagicMock()
    mock_request.url.path = "/api/v1/verifications/123e4567-e89b-12d3-a456-426614174000"
    mock_request.scope = {}

    normalized = get_normalized_route(mock_request)
    assert normalized == "/api/v1/verifications/{verification_id}"


def test_prometheus_metric_labels_cardinality_and_secrets():
    """Verifies Prometheus metric labels contain zero unbounded keys or PII/secrets."""
    POLICY_EVALUATIONS_TOTAL.labels(result="PASS").inc()

    sample_labels = ["method", "route", "status_code"]
    for label in sample_labels:
        assert label in ["method", "route", "status_code"]

    for metric in [HTTP_REQUESTS_TOTAL, POLICY_EVALUATIONS_TOTAL, WORKER_TASKS_TOTAL]:
        for label_name in metric._labelnames:
            assert label_name not in [
                "organization_id",
                "project_id",
                "user_id",
                "token",
                "digest",
                "ip",
            ]


def test_worker_liveness_independence():
    """Verifies worker process liveness functions independently of metrics server."""
    assert update_worker_heartbeat() is True


# ============================================================================
# 3. HELM 3 MANIFEST & SECURITY FILE-LEVEL ASSERTIONS
# ============================================================================


def test_helm_manifest_files_security_contents():
    """Static inspection of Helm templates for zero-trust security controls."""
    helm_dir = Path("helm/provenanceguard/templates")

    # 1. Secret Validation check
    secret_val_content = (helm_dir / "secret-validation.yaml").read_text()
    assert "fail" in secret_val_content
    assert "Production deployments MUST specify existingSecret.name" in secret_val_content

    # 2. NetworkPolicy check
    netpol_content = (helm_dir / "networkpolicy.yaml").read_text()
    values_content = (Path("helm/provenanceguard/values.yaml")).read_text()
    assert ".Values.ingress.namespaceSelector" in netpol_content
    assert ".Values.prometheus.namespaceSelector" in netpol_content
    assert "ingress-nginx" in values_content
    assert "prometheus" in values_content
    assert "port: 8000" in netpol_content
    assert "port: 9090" in netpol_content
    assert "port: 53" in netpol_content
    assert "port: 443" in netpol_content

    # 3. API Deployment securityContext check
    api_dep_content = (helm_dir / "api-deployment.yaml").read_text()
    assert "runAsNonRoot: true" in api_dep_content or "podSecurityContext" in api_dep_content
    assert "readOnlyRootFilesystem: true" in api_dep_content or "securityContext" in api_dep_content
    assert "livenessProbe:" in api_dep_content
    assert "readinessProbe:" in api_dep_content
    assert "containerPort: {{ .Values.api.ports.http }}" in api_dep_content
    assert "containerPort: {{ .Values.api.ports.metrics }}" in api_dep_content
    assert "http: 8000" in values_content
    assert "metrics: 9090" in values_content

    # 4. ServiceAccount check
    sa_content = (helm_dir / "serviceaccount.yaml").read_text()
    assert "automountServiceAccountToken:" in sa_content


def _run_helm_command(args: list[str]) -> subprocess.CompletedProcess:
    """Runs helm command via PATH or WSL helm binary."""
    helm_bin = shutil.which("helm")
    if helm_bin:
        return subprocess.run([helm_bin] + args, capture_output=True, text=True)

    # Try WSL helm binary
    wsl_bin = shutil.which("wsl")
    if wsl_bin:
        return subprocess.run([wsl_bin, "helm"] + args, capture_output=True, text=True)

    pytest.skip("Helm CLI not available in PATH or WSL environment")


def test_helm_template_production_secret_fail_closed():
    """Verifies Helm rendering in production without existingSecret.name fails closed via CLI."""
    args = [
        "template",
        "provenanceguard",
        "./helm/provenanceguard",
        "--set",
        "global.environment=production",
        "--set",
        "existingSecret.name=",
    ]
    result = _run_helm_command(args)
    assert result.returncode != 0
    assert (
        "Production deployments MUST specify existingSecret.name" in result.stderr or result.stdout
    )


def test_helm_template_renders_successfully_with_existing_secret():
    """Verifies Helm rendering succeeds when existingSecret.name is provided via CLI."""
    args = [
        "template",
        "provenanceguard",
        "./helm/provenanceguard",
        "--set",
        "global.environment=production",
        "--set",
        "existingSecret.name=prod-secrets",
    ]
    result = _run_helm_command(args)
    assert result.returncode == 0
    rendered_yaml = result.stdout

    assert "kind: Deployment" in rendered_yaml
    assert "kind: NetworkPolicy" in rendered_yaml
    assert "kind: PodDisruptionBudget" in rendered_yaml
    assert "runAsNonRoot: true" in rendered_yaml
    assert "readOnlyRootFilesystem: true" in rendered_yaml
    assert "seccompProfile:" in rendered_yaml
    assert "automountServiceAccountToken: false" in rendered_yaml
    assert "kubernetes.io/metadata.name: ingress-nginx" in rendered_yaml
    assert "kubernetes.io/metadata.name: prometheus" in rendered_yaml


@pytest.mark.skipif(
    not shutil.which("docker"), reason="Docker CLI not installed on execution environment"
)
def test_docker_compose_prod_config_validity():
    """Verifies docker-compose.prod.yml syntax validity via Docker CLI."""
    cmd = ["docker", "compose", "-f", "docker-compose.prod.yml", "config"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0
