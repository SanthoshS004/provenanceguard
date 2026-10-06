# ADR-010: Environment Configuration Management & Secrets Isolation

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Systems Engineering Team

## 1. Context
ProvenanceGuard requires environment-specific parameters (development, staging, production, worker, logging) while ensuring zero hardcoded secrets in source files or default configs.

## 2. Problem
Mixing configuration and secrets leads to accidental secret commits in Git repositories.

## 3. Decision
- Environment parameters are stored in version-controlled YAML files under `config/` (`development.yaml`, `staging.yaml`, `production.yaml`, `worker.yaml`, `logging.yaml`).
- Secrets (database passwords, Redis credentials, JWT secret keys, S3 access keys) MUST be loaded dynamically via environment variables (`PG_DB_PASSWORD`, `PG_SECRET_KEY`) or secret management service adapters (AWS Secrets Manager / Vault).

## 4. Alternatives Considered
- **Single `.env` File**: Useful for local dev, but unsafe if committed to Git.

## 5. Security Consequences
- Completely eliminates hardcoded credentials in source control.

## 6. Operational Consequences
- Deployments specify `PG_ENV=production` and inject environment variables via Kubernetes Secret / Docker Compose.

## 7. Future Reconsideration Conditions
- Re-evaluate if HashiCorp Vault dynamic secret lease renewal integration is required.
