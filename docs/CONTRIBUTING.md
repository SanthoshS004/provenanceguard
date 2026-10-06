# Contributing to ProvenanceGuard

Thank you for contributing to ProvenanceGuard! This project enforces strict security boundaries, code formatting, type checking, and unit testing guidelines.

---

## 1. Contribution Workflow

1. **Check Requirements Traceability**: Ensure your proposed feature or fix maps to a requirement in `docs/REQUIREMENTS-TRACEABILITY.md`.
2. **Branching Strategy**:
   - `main`: Protected production-ready releases.
   - `develop`: Primary integration branch.
   - `feature/*`: Feature development branches.
   - `fix/*`: Bug fix branches.
   - `security/*`: Security patches and sandbox hardenings.

3. **Pull Request Requirements**:
   - All tests in `tests/` must pass (`pytest`).
   - Ruff linter and formatter must pass cleanly (`ruff check .`).
   - New code must include unit tests and docstrings.
   - Any architectural changes must be accompanied by an ADR in `docs/adr/`.
