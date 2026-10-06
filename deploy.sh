#!/usr/bin/env bash
# ProvenanceGuard Automated Production Deployment Script
# Execute on Ubuntu Linux VPS: bash deploy.sh

set -euo pipefail

echo "=================================================="
echo " Starting ProvenanceGuard Production Deployment  "
echo "=================================================="

# 1. Ensure required tools exist
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker is required but not installed. Aborting."; exit 1; }
command -v docker-compose >/dev/null 2>&1 || docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose is required. Aborting."; exit 1; }

# Determine compose command
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
else
    DOCKER_COMPOSE="docker-compose"
fi

# 2. Initialize directory structure and secrets
echo "[1/6] Initializing secrets and environment..."
mkdir -p secrets

if [ ! -f secrets/db_password.txt ]; then
    echo "Generating secure database password..."
    openssl rand -base64 24 | tr -d '\n' > secrets/db_password.txt
    chmod 600 secrets/db_password.txt
fi

if [ ! -f .env ]; then
    echo "Creating .env file from .env.production.example..."
    cp .env.production.example .env
fi

# 3. Build containers
echo "[2/6] Building production Docker containers..."
$DOCKER_COMPOSE -f docker-compose.prod.yml build --parallel

# 4. Spin up PostgreSQL and Redis first
echo "[3/6] Starting stateful services (PostgreSQL, Redis, MinIO)..."
$DOCKER_COMPOSE -f docker-compose.prod.yml up -d postgres redis minio

echo "Waiting for database and object storage health..."
sleep 5

# 5. Run Alembic Database Migrations
echo "[4/6] Executing Alembic database migrations..."
$DOCKER_COMPOSE -f docker-compose.prod.yml run --rm api python -m alembic upgrade head

# 6. Launch API, Worker, and Dashboard
echo "[5/6] Launching ProvenanceGuard API, Worker, and Dashboard..."
$DOCKER_COMPOSE -f docker-compose.prod.yml up -d

# 7. Post-deployment Readiness Verification
echo "[6/6] Verifying system readiness..."
sleep 5

READINESS_URL="http://127.0.0.1:8000/api/v1/health/readiness"
HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$READINESS_URL" || echo "000")

if [ "$HTTP_STATUS" -eq 200 ]; then
    echo "SUCCESS: ProvenanceGuard is UP and HEALTHY!"
    curl -s "$READINESS_URL" | python3 -m json.tool || true
else
    echo "WARNING: Readiness check returned HTTP $HTTP_STATUS. Checking container logs..."
    $DOCKER_COMPOSE -f docker-compose.prod.yml ps
fi

echo "=================================================="
echo " Deployment Complete!                            "
echo " Ensure your Reverse Proxy (Caddy/Nginx) is running"
echo "=================================================="
