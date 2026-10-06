# ProvenanceGuard Operations & Maintenance Guide

This document defines operational procedures, monitoring metrics, backup strategies, and incident response runbooks for ProvenanceGuard operators.

---

## 1. Key Metrics & Observability

ProvenanceGuard exposes Prometheus-compatible metrics at `/metrics`:

| Metric Name | Type | Description | Target SLA / Alert Threshold |
|---|---|---|---|
| `pg_verification_total` | Counter | Total verification runs by organization and decision (`PASS`, `BLOCK`). | Baseline tracking |
| `pg_verification_blocked_total` | Counter | Total artifacts blocked by policy enforcement. | Spike alert (> 50/hour) |
| `pg_verification_duration_seconds` | Histogram | Latency distribution of verification jobs. | p95 < 15.0s |
| `pg_worker_failures_total` | Counter | Count of analysis worker crashes or timeouts. | Alert if > 1% failure rate |
| `pg_queue_depth` | Gauge | Number of pending verification jobs in Redis. | Alert if > 100 queued |

---

## 2. Backup & Disaster Recovery

- **PostgreSQL Database**: Daily automated WAL archiving + full logical snapshots (`pg_dump`). RPO: 5 minutes, RTO: 1 hour.
- **Object Storage (MinIO / S3)**: Cross-region bucket replication for raw artifact binaries and reference build logs.

---

## 3. Incident Response Runbook (Verification Outage / Fail-Closed)

If the API or worker cluster becomes unresponsive:
1. **Behavior**: CI/CD pipelines configured with `fail_closed: true` will block releases automatically (Exit code 3/1).
2. **Triage Step 1**: Check Redis queue depth and Celery worker health: `docker compose logs worker`.
3. **Triage Step 2**: Inspect database pool connections: `SELECT count(*) FROM pg_stat_activity;`.
4. **Emergency Bypass**: If an emergency hotfix deployment is required during a verifier outage, administrators must issue an ephemeral `EXPLICIT_BYPASS` signed emergency token logged in audit logs.
