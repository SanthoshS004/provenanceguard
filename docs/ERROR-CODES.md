# ProvenanceGuard Machine-Readable Error Codes

This document establishes the official stable error-code registry for ProvenanceGuard. All REST API responses, CLI error outputs, worker failure reports, and SDK exceptions must return a registered `PG-XXXX` error code.

---

## 1. Error Code Registry

| Error Code | Error Constant | Category | HTTP Status | Description |
|---|---|---|---|---|
| **PG-1001** | `INVALID_ARTIFACT` | Ingestion | 400 | Artifact file is malformed, unrecognized format, or corrupted header. |
| **PG-1002** | `ARTIFACT_TOO_LARGE` | Ingestion | 413 | Uploaded artifact exceeds max size limit (2GB). |
| **PG-1003** | `UNSUPPORTED_MEDIA_TYPE` | Ingestion | 415 | Media type is not supported by available analyzers. |
| **PG-2001** | `PROVENANCE_INVALID` | Provenance | 422 | Provenance payload failed SLSA/in-toto schema validation. |
| **PG-2002** | `PROVENANCE_MISSING` | Provenance | 422 | Required SLSA provenance attestation was not provided. |
| **PG-2003** | `PROVENANCE_TAMPERED` | Provenance | 422 | Provenance DSSE signature or digest cross-reference mismatch. |
| **PG-2501** | `SIGNATURE_INVALID` | Signature | 422 | Cosign / Sigstore signature verification failed. |
| **PG-2502** | `SIGNATURE_MISSING` | Signature | 422 | Policy requires Cosign signature, but none was attached. |
| **PG-2503** | `UNTRUSTED_SIGNER` | Signature | 422 | Signer identity certificate SAN / issuer does not match policy. |
| **PG-3001** | `POLICY_BLOCKED` | Policy | 200 / 409 | Policy evaluation yielded a `BLOCK` decision (Exit Code 1). |
| **PG-3002** | `POLICY_SYNTAX_ERROR` | Policy | 400 | Policy YAML configuration syntax is invalid. |
| **PG-3003** | `POLICY_NOT_FOUND` | Policy | 404 | Specified policy ID or file does not exist. |
| **PG-4001** | `WORKER_TIMEOUT` | Worker | 504 | Isolated analysis worker exceeded maximum time budget (300s). |
| **PG-4002** | `WORKER_OOM` | Worker | 500 | Isolated analysis worker exceeded memory allocation cap (2GB). |
| **PG-4003** | `PARSER_CRASH` | Worker | 500 | Analyzer parser crashed while inspecting hostile artifact. |
| **PG-5001** | `INTERNAL_ERROR` | System | 500 | Unhandled internal exception in verifier control plane. |
| **PG-5002** | `STORAGE_UNAVAILABLE` | System | 503 | MinIO / S3 object storage or PostgreSQL connection failed. |

---

## 2. API Error Response Payload Format

```json
{
  "error": {
    "code": "PG-3001",
    "constant": "POLICY_BLOCKED",
    "message": "Artifact verification failed due to policy rule violations.",
    "details": [
      {
        "severity": "HIGH",
        "category": "FUNCTION_ADDED",
        "subject": "send_data",
        "explanation": "Production binary contains function 'send_data' absent from reference build."
      }
    ],
    "verification_id": "vr_2026_000102",
    "timestamp": "2026-09-04T18:45:00Z"
  }
}
```
