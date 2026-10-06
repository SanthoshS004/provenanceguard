# ProvenanceGuard REST API Versioning Strategy

This document details the versioning lifecycle, deprecation guidelines, and compatibility policies for the ProvenanceGuard REST API.

---

## 1. Version Path Convention

All ProvenanceGuard REST API endpoints are strictly versioned using URI path prefixes:

```
https://provenanceguard.enterprise.internal/api/v1/...
```

### Supported API Versions
- `/api/v1` — **Active Current Version** (OpenAPI 3.1.2 Compatible).

---

## 2. OpenAPI Specification Standard

- The API specification is auto-generated using FastAPI and adheres strictly to **OpenAPI 3.1.2**.
- Interactive OpenAPI documentation is accessible at `/api/v1/docs` (Swagger UI) and `/api/v1/redoc` (ReDoc).
- JSON schema specification output is exported at `/api/v1/openapi.json`.

---

## 3. Backward Compatibility Guarantees

Within a major version family (e.g. `/api/v1`):
1. **Non-Breaking Additions Allowed**: New optional request body fields, new response object attributes, or new endpoints may be introduced without incrementing the major version.
2. **No Field Removals**: Existing response fields or request parameters will NOT be removed or renamed within `/api/v1`.
3. **Stable Enums**: Stable error codes (`PG-XXXX`) and decision enum strings (`PASS`, `PASS_WITH_WARNING`, `BLOCK`) remain fixed.

---

## 4. Deprecation & Breaking Change Policy

When a breaking API change is required:
1. A new major version URI prefix (e.g., `/api/v2`) will be introduced.
2. The legacy version (`/api/v1`) enters a **6-month minimum deprecation window**.
3. Deprecated endpoints emit HTTP response headers:
   - `Deprecation: @1780000000` (Unix timestamp)
   - `Sunset: Sat, 01 May 2027 00:00:00 GMT`
   - `Link: <https://provenanceguard.internal/docs/migration-v2>; rel="successor-version"`
