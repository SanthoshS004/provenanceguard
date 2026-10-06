# Enterprise Operations & Disaster Recovery Runbook

This document details the operational procedures, failure mode recovery workflows, disaster recovery targets, and backup/restore protocols for **ProvenanceGuard**.

---

## 1. Operational Disaster Recovery Targets

| Metric | Target | Verification Protocol |
| :--- | :--- | :--- |
| **Recovery Point Objective (RPO)** | **Target < 1 minute** | Continuous PostgreSQL Write-Ahead Logging (WAL) archiving to S3/MinIO. |
| **Recovery Time Objective (RTO)** | **Target < 15 minutes** | Automated database snapshot restoration and container spinup via Infrastructure-as-Code. |

---

## 2. PostgreSQL Backup & Point-in-Time Recovery (PITR)

### 2.1 Daily Logical Backup (`pg_dump`)
Logical backups provide portable schema and data exports for disaster recovery and staging migration.

```bash
# Execute organization-filtered or full logical database backup
pg_dump \
  --host=${PGHOST} \
  --username=${PGUSER} \
  --dbname=${PGDATABASE} \
  --format=custom \
  --file=/backups/provenanceguard_$(date +%Y%m%d_%H%M%S).dump

# Verify backup integrity
pg_restore --list /backups/provenanceguard_$(date +%Y%m%d_%H%M%S).dump > /dev/null
```

### 2.2 Continuous Physical WAL Archiving (PITR Target RPO < 1 min)
Configure `postgresql.conf` for continuous WAL archiving:

```ini
archive_mode = on
archive_command = 'aws s3 cp %p s3://provenanceguard-wal-backups/%f'
wal_level = replica
archive_timeout = 60
```

### 2.3 Disaster Recovery Restoration Procedure (Target RTO < 15 mins)
To restore PostgreSQL to a specific point in time (e.g. before accidental corruption):

1. Stop application gateway services (`provenanceguard-api`, `provenanceguard-worker`).
2. Restore base physical backup to new database instance directory.
3. Create `recovery.signal` and configure `postgresql.conf`:

```ini
restore_command = 'aws s3 cp s3://provenanceguard-wal-backups/%f %p'
recovery_target_time = '2026-09-10 14:00:00 UTC'
```

4. Start PostgreSQL and monitor recovery progress in logs.
5. Verify audit log gapless sequence integrity using `AuditIntegrityVerifier`.

---

## 3. Redis Ephemeral Broker Failure & Outbox Recovery

### 3.1 Architecture Invariant
PostgreSQL is the **sole durable source of truth** for verification requests and outbox events (`outbox_events` table). Redis acts strictly as an ephemeral task distribution broker.

### 3.2 Outage Recovery Procedure
If Redis crashes, drops connections, or suffers unrecoverable node failure:

1. Redis broker failure does **NOT** cause outbox data loss. Pending verification runs remain safely stored in PostgreSQL with status `PENDING` / `QUEUED`.
2. Provision a new Redis instance or restart the Redis service.
3. Restart `provenanceguard-worker` processes.
4. The background outbox dispatcher reads un-dispatched `PENDING` outbox events from PostgreSQL, acquires atomic claims (`status='CLAIMED'`), and re-enqueues jobs to Redis.
5. At-least-once task execution semantics and worker idempotency prevent duplicate processing.

---

## 4. MinIO / S3 Object Storage Cross-Region Replication & Object Locking

### 4.1 Bucket Immutability (WORM Locking)
To prevent out-of-band artifact or attestation tampering on object storage:

```bash
# Enable object lock on production artifact bucket
mc retention set --default governance 365d myminio/provenanceguard-artifacts
```

### 4.2 Cross-Region Replication (CRR)
Configure asynchronous bucket replication to a secondary disaster recovery region:

```bash
# Set up continuous S3/MinIO bucket replication
mc mirror --watch myminio/provenanceguard-artifacts dr-minio/provenanceguard-artifacts-dr
```

---

## 5. Emergency Infrastructure Recovery Protocol

> [!IMPORTANT]
> **No Bypass Tokens**
> ProvenanceGuard does **NOT** support cryptographic emergency policy bypass tokens or backdoor override flags. All software supply-chain verification and policy evaluation remain strictly active during and after emergency infrastructure recovery.

### 5.1 Infrastructure Incident Recovery Steps
In the event of severe cloud region outage or multi-service infrastructure failure:

1. **Database Restoration**: Restore PostgreSQL from physical WAL backup to secondary region DB cluster.
2. **Object Storage Restoration**: Promote secondary CRR bucket (`provenanceguard-artifacts-dr`) to primary.
3. **Application Redeployment**: Deploy `provenanceguard-api` and `provenanceguard-worker` containers via `docker-compose.prod.yml` or Helm chart.
4. **Audit Integrity Audit**: Execute `AuditIntegrityVerifier.verify_chain()` against all active tenant chains to confirm zero sequence gaps or record tampering during failover.
5. **Resume Traffic**: Switch DNS / Load Balancer endpoints to restored instance.
