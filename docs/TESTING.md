# ProvenanceGuard Testing Strategy & Scaffolding

This document outlines the multi-layered testing philosophy and test suite organization for ProvenanceGuard.

---

## 1. Test Suite Categories

```
tests/
├── unit/               # Core domain objects, policy rules, parser logic (Fast, zero dependencies)
├── integration/        # API + Database, Worker + Queue, Storage integrations
├── security/           # Malformed input, path traversal, zip bombs, cross-tenant isolation, sandbox limits
├── attack-scenarios/   # Defensive validation labs (clean, new-function, modified-function, dep-substitution)
├── performance/        # API latency benchmarks, artifact processing throughput
└── regression/         # Bug regressions and edge case verification
```

---

## 2. Test Execution Commands

```bash
# Run unit tests only
pytest tests/unit

# Run security & sandboxing tests
pytest tests/security

# Run attack scenario validation labs
pytest tests/attack-scenarios

# Run complete test suite with coverage report
pytest --cov=provenanceguard --cov-report=term-missing
```

---

## 3. Mandatory Security Test Scenarios

1. **Hostile Payload Parsing**: Tests feed malformed ELF headers, corrupted tar archives, and oversized JSON files into analyzers to ensure no host crashes or buffer overflows occur.
2. **Cross-Tenant Access Attempt**: Tests attempt to query Tenant B artifacts using Tenant A credentials, asserting `403 Forbidden` or `404 Not Found`.
3. **Fail-Closed Strategy**: Tests simulate backend service unavailability, verifying that CI verification defaults to `BLOCK` (`Exit code 1/3`).
