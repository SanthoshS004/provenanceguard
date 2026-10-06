# ProvenanceGuard Structured Logging Standard

This document defines the structured JSON logging standard enforced across all ProvenanceGuard microservices, workers, CLI commands, and analyzers.

---

## 1. JSON Log Format Specification

All log outputs must be single-line JSON objects emitted to `stdout` (or `stderr` for errors).

### Required Log Schema
```json
{
  "timestamp": "2026-09-04T18:45:00.123456Z",
  "service": "provenanceguard-api",
  "severity": "INFO",
  "trace_id": "tr-9a8b7c6d5e4f",
  "request_id": "req-1234567890",
  "organization_id": "org_987",
  "project_id": "proj_456",
  "verification_id": "vr_2026_000102",
  "event": "VERIFICATION_COMPLETED",
  "message": "Verification completed for artifact payment-service:v4.2.1",
  "extra": {
    "artifact_digest": "sha256:7f3a91c...",
    "risk_score": 82,
    "decision": "BLOCK"
  }
}
```

---

## 2. Standard Log Fields

| Field Name | Type | Description | Example |
|---|---|---|---|
| `timestamp` | ISO-8601 String | UTC timestamp with microsecond resolution. | `"2026-09-04T18:45:00.123Z"` |
| `service` | String | Subsystem name (`api`, `worker`, `cli`, `builder`). | `"provenanceguard-worker"` |
| `severity` | Enum String | Log level: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`. | `"WARNING"` |
| `trace_id` | String | Distributed tracing correlation identifier. | `"tr-4a5b6c7d"` |
| `request_id` | String | HTTP API request correlation identifier. | `"req-890123"` |
| `organization_id` | String | Multi-tenant organization identifier (if scoped). | `"org_corp_01"` |
| `project_id` | String | Project identifier (if scoped). | `"proj_payments"` |
| `verification_id` | String | Verification run identifier (if applicable). | `"vr_2026_000102"` |
| `event` | String | High-level event identifier (uppercase snake_case). | `"ARTIFACT_INGESTED"` |
| `message` | String | Human-readable log message. | `"Artifact ingested successfully."` |

---

## 3. Forbidden Fields & Sanitization Policy

### Strictly Forbidden in Logs ❌
Under no circumstances may any log statement record:
- User passwords, password hashes, or salt strings.
- Bearer tokens, JWT tokens, OAuth client secrets, or API keys.
- Private SSH / Cosign signing keys or TLS private keys.
- CI service account secrets or cloud provider credentials (`AWS_SECRET_ACCESS_KEY`).
- Raw binary payloads or un-sanitized user file contents.

### Automated Scrubbing Rule
Logging handlers automatically filter dictionary keys matching the regex:
`(?i)(password|token|secret|private_key|auth|bearer|credential)`
Matching values are replaced with `"[REDACTED]"`.
