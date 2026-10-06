# ProvenanceGuard Production Deployment Manual

> **Official Classification**: **Publicly hosted, production-style functional prototype**

This manual outlines the production deployment procedure for **ProvenanceGuard** on an Ubuntu Linux Virtual Private Server (VPS) with automatic HTTPS (SSL), single-entry reverse proxying via Caddy, pinned container images, dedicated Docker container bridge networking (`provenanceguard_net`), persistent data storage, automated multi-component backups, and zero-trust security controls.

---

## 1. Container Version Policy & Review

> **Version Policy Statement**: Container versions are pinned and compatibility-reviewed; compatible security/current releases are used where regression testing confirms compatibility.

| Service / Component | Pinned Version Tag | Purpose |
| :--- | :--- | :--- |
| **Caddy Reverse Proxy** | `caddy:2.7.6-alpine` | Edge reverse proxy & automatic TLS/HTTPS |
| **PostgreSQL Database** | `postgres:16.4-alpine` | Relational storage & RLS tenant security |
| **Redis Cache / Queue** | `redis:7.2.5-alpine` | ARQ task queue broker & rate-limiting backend |
| **MinIO Object Storage** | `minio/minio:RELEASE.2024-03-21T23-13-43Z` | Object storage for software build evidence & artifacts |
| **Python Base Image** | `python:3.11.9-slim` | FastAPI API gateway & ARQ worker runtime |
| **Node.js Builder** | `node:20.12.2-alpine` | React SPA static frontend compiler |
| **Nginx SPA Server** | `nginx:1.25.5-alpine-slim` | Static asset web server for compiled React SPA |

---

## 2. Secrets & JWT Private Key Policy

### JWT Private Key Handling
- **Production Verification**: The API Gateway strictly requires `PG_JWT_PUBLIC_KEY` to verify RS256 signatures of incoming JWT tokens.
- **Private Key Requirement**: In strict production mode (`PG_ENV=production` with `ENABLE_DEV_TOKEN_ISSUANCE=false`), the RSA private key is **NOT required on the production VPS**. Token issuance is handled by external Identity Providers (OIDC) or authentication uses stateful `pg_live_` API keys.
- **Demo/Testing Exception**: If dev token issuance is explicitly enabled for demo/testing (`ENABLE_DEV_TOKEN_ISSUANCE=true`), store `private.pem` exclusively inside `/opt/provenanceguard/secrets/private.pem`:
  - Enforce permission: `chmod 600 secrets/private.pem`
  - Never place private keys in the application root directory.
  - Never commit key files to version control (`.gitignore` excludes `secrets/*` and `*.pem`).

---

## 3. Production Architecture Overview

```
Internet (Browser / CI / CLI)
             │
     HTTPS :443 (HTTP :80 Redirects)
             │
             ▼
┌──────────────────────────────────────────┐
│ Caddy Reverse Proxy & Auto HTTPS         │
│ (caddy:2.7.6-alpine)                     │
└──────────────────┬───────────────────────┘
                   │  Internal Docker Network: provenanceguard_net
         ┌─────────┴─────────┐
         │ (api:8000)        │ (dashboard:8080)
         ▼                   ▼
┌────────────────────────────────────────┐ ┌──────────────────┐
│ FastAPI Backend Gateway                │ │ Dashboard SPA    │
│ (Uvicorn REST API)                     │ │ (Nginx Container)│
└────────────────┬───────────────────────┘ └──────────────────┘
                 │
 ┌───────────────┼────────────────┐
 ▼               ▼                ▼
┌──────────────┐ ┌──────────────┐ ┌─────────────────┐
│ PostgreSQL 16│ │ Redis 7 Queue│ │ MinIO S3        │
│ (Vol: pg_data│ │ (ARQ Broker) │ │ (Vol: minio)    │
└──────────────┘ └──────┬───────┘ └─────────────────┘
                        │
                        ▼
               ┌─────────────────┐
               │ ARQ Worker      │
               │ (Non-Root/tmpfs)│
               └─────────────────┘
```

---

## 4. Real Domain Configuration Instructions

Before public deployment, replace template domain `provenanceguard.example.com` with your actual registered domain across all configuration files:

| File | Parameter to Update | Example Real Domain |
| :--- | :--- | :--- |
| **`Caddyfile`** | Site block header | `provenanceguard.yourdomain.com` |
| **`.env`** | `PG_CORS_ALLOWED_ORIGINS` | `https://provenanceguard.yourdomain.com` |
| **GitHub Secrets** | `PROVENANCEGUARD_URL` | `https://provenanceguard.yourdomain.com` |
| **`robots.txt`** | `Sitemap:` directive | `https://provenanceguard.yourdomain.com/sitemap.xml` |
| **`sitemap.xml`** | `<loc>` tag | `https://provenanceguard.yourdomain.com/` |
| **`dashboard/index.html`** | OpenGraph `og:url` | `https://provenanceguard.yourdomain.com/` |

---

## 5. Public Port Audit & Firewall Rules

Only ports 80 and 443 are publicly reachable on the host network.

| Service | Port | Upstream Binding | Public Exposure |
| :--- | :--- | :--- | :--- |
| **HTTP (Caddy)** | `80` | `0.0.0.0:80` | **YES** (Redirects to 443) |
| **HTTPS (Caddy)** | `443` | `0.0.0.0:443` | **YES** |
| **PostgreSQL** | `5432` | `127.0.0.1:5432` / `provenanceguard_net` | **NO** (Isolated) |
| **Redis** | `6379` | `127.0.0.1:6379` / `provenanceguard_net` | **NO** (Isolated) |
| **MinIO S3 API** | `9000` | `127.0.0.1:9000` / `provenanceguard_net` | **NO** (Isolated) |
| **MinIO Console** | `9001` | `127.0.0.1:9001` / `provenanceguard_net` | **NO** (Isolated) |
| **FastAPI Backend** | `8000` | `127.0.0.1:8000` / `api:8000` | **NO** (Isolated) |
| **Dashboard Container** | `8080` | `127.0.0.1:8080` / `dashboard:8080` | **NO** (Isolated) |

---

## 6. Automated Backup & Disaster Recovery

- **Multi-Component Backup**: Executed via `backup_provenanceguard.sh`.
  - Database Dump: `/opt/provenanceguard/backups/db_provenanceguard_prod_YYYYMMDD_HHMMSS.dump`
  - MinIO Storage Archive: `/opt/provenanceguard/backups/minio_artifacts_YYYYMMDD_HHMMSS.tar.gz`
  - Retention: 14-day rolling pruning.

> **Backup Limitation**: Offsite backup replication is not implemented. Local VPS backups protect against container/database corruption, but do not protect against total host hardware destruction unless paired with external S3 sync (`rclone`).

---

## 7. Step-by-Step VPS Deployment Instructions

```bash
# 1. System updates & firewall
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl git ufw jq openssl

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp comment 'SSH'
sudo ufw allow 80/tcp comment 'HTTP'
sudo ufw allow 443/tcp comment 'HTTPS'
sudo ufw --force enable

# 2. Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
newgrp docker

# 3. Setup workspace & secrets
sudo mkdir -p /opt/provenanceguard
sudo chown -R $USER:$USER /opt/provenanceguard
cd /opt/provenanceguard

mkdir -p secrets
openssl rand -base64 24 | tr -d '\n' > secrets/db_password.txt
chmod 600 secrets/db_password.txt
cp .env.production.example .env

# Generate RS256 JWT Public Key (Private key optional under secrets/private.pem if dev token issuance enabled)
openssl genpkey -algorithm RSA -out secrets/private.pem -pkeyopt rsa_keygen_bits:2048
chmod 600 secrets/private.pem
openssl rsa -in secrets/private.pem -pubout -out secrets/public.pem
PUB_KEY=$(awk 'NF {sub(/\r/, ""); printf "%s\\n", $0}' secrets/public.pem)
echo "PG_JWT_PUBLIC_KEY=\"$PUB_KEY\"" >> .env

FERNET_KEY=$(python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")
echo "PG_WEBHOOK_ENCRYPTION_KEY_V1=\"$FERNET_KEY\"" >> .env

# 4. Set public domain in .env & Caddyfile
# PG_CORS_ALLOWED_ORIGINS=https://provenanceguard.yourdomain.com

# 5. Execute safe deployment script
chmod +x deploy.sh backup_provenanceguard.sh restore_provenanceguard.sh
./deploy.sh

# 6. Enable systemd boot auto-start and daily backup timer
sudo cp provenanceguard.service /etc/systemd/system/
sudo cp provenanceguard-backup.service /etc/systemd/system/
sudo cp provenanceguard-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable provenanceguard.service
sudo systemctl enable --now provenanceguard-backup.timer
```
