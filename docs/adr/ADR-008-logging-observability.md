# ADR-008: Structured JSON Logging & Observability Standard

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Operations & Security Team

## 1. Context
Troubleshooting, security auditing, and SIEM integration across distributed API, worker, and builder processes require consistent, machine-readable log output.

## 2. Problem
Unstructured plain-text logs hamper automated SIEM parsing and risk accidental secret leakage.

## 3. Decision
Enforce single-line structured JSON logs across all services adhering to `docs/LOGGING-STANDARD.md`. Include standard correlation headers (`trace_id`, `request_id`, `verification_id`, `organization_id`). Implement automated log scrubbers to redact sensitive token/key fields.

## 4. Alternatives Considered
- **Plain Text Logs**: Hard to parse in Datadog/ELK/Splunk.

## 5. Security Consequences
- Prevents accidental logging of secrets or bearer credentials.

## 6. Operational Consequences
- Seamless ingestion into Grafana Loki, Elasticsearch, or Datadog.

## 7. Future Reconsideration Conditions
- Re-evaluate if OpenTelemetry tracing exporters need to be compiled natively into C analyzers.
