# ProvenanceGuard Local Development Guide

This document provides setup and operational instructions for developers building and testing ProvenanceGuard.

---

## 1. Prerequisites

- **Python**: Python 3.11+
- **Container Engine**: Docker Desktop or Podman with Docker Compose v2+
- **Tooling**: `uv` or `pip`, `git`, `ruff`, `pytest`

---

## 2. Environment Setup

```bash
# Clone repository
git clone https://github.com/provenanceguard/provenanceguard.git
cd provenanceguard

# Create and activate virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.venv\Scripts\activate

# Install package in editable mode with development dependencies
pip install -e .[dev]
```

---

## 3. Running Development Infrastructure

ProvenanceGuard relies on PostgreSQL 16, Redis 7, and MinIO (S3-compatible object storage) during local development:

```bash
# Start containerized services in background
docker compose up -d

# Verify container health
docker compose ps

# Stop containerized services
docker compose down
```

---

## 4. Code Formatting, Linting & Type Checking

```bash
# Run Ruff linter & formatter
ruff check .
ruff format . --check

# Run pytest unit & integration tests
pytest
```
