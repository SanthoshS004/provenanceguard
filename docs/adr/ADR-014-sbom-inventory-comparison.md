# ADR-014: SPDX & CycloneDX SBOM Normalization and Deterministic Package-Inventory Comparison

- **Status**: ACCEPTED
- **Date**: 2026-09-06
- **Authors**: Principal Architecture Team

## 1. Context
ProvenanceGuard requires capability to analyze Software Bill of Materials (SBOM) documents submitted alongside software artifacts to detect dependency supply-chain tampering, unauthorized component additions/removals, version shifts, license modifications, and package checksum mismatches.

## 2. Decision

### 2.1 Supported Document Specifications
The SBOM subsystem accepts and normalizes documents strictly conforming to:
- **SPDX**: v2.2 and v2.3 JSON documents (`spdxVersion` $\in$ `{"SPDX-2.2", "SPDX-2.3"}`).
- **CycloneDX**: v1.4 and v1.5 JSON documents (`bomFormat == "CycloneDX"` and `specVersion` $\in$ `{"1.4", "1.5"}`).

Unsupported formats or versions raise explicit `UNSUPPORTED_VERSION` exceptions.

### 2.2 Scope & Boundary Limits
Phase 7 compares **normalized package inventory evidence ONLY**. It explicitly does **NOT** perform graph-based dependency relationship comparison or SPDX package relationship graph matching (deferred to a future separate phase).

### 2.3 Package Identity vs Version Separation
Package version is explicitly **excluded** from `PackageIdentity` to enable version shift detection (`VERSION_CHANGED`) without misclassifying version updates as `REMOVED_PACKAGE` + `ADDED_PACKAGE`.

Identity Resolution Hierarchy:
1. **Canonical PURL Identity**: Parsed per Package URL specification (`pkg:type/namespace/name?qualifiers#subpath`), retaining ecosystem `type`, `namespace`, `name`, `qualifiers`, and `subpath`, while excluding `version`.
2. **Canonical Name + Supplier**: Canonical `name` + `supplier` string (version-free).
3. **Unresolved / Ambiguous**: Name-only fallback is prohibited. Identity resolution status produces explicit values (`UNIQUE`, `DUPLICATE`, `AMBIGUOUS`, `UNRESOLVED`). Ambiguous packages are never arbitrarily matched.

### 2.4 Completeness Governance & Absence Invariant
Inventory completeness state is categorized as `COMPLETE`, `PARTIAL`, or `UNKNOWN`.
**Mandatory Invariant**: *"Absence in incomplete/unknown evidence must never generate an absence-based package delta."*
- `REMOVED_PACKAGE` requires Target inventory to be `COMPLETE`.
- `ADDED_PACKAGE` requires Reference inventory to be `COMPLETE`.
- Positive evidence present on matched identities can always produce `VERSION_CHANGED`, `LICENSE_CHANGED`, and `CHECKSUM_MISMATCH`.

### 2.5 Checksum Comparison Semantics
Checksum comparison identity is: `matched package identity` + `normalized checksum algorithm`.
- Algorithm names are normalized deterministically (e.g. `sha256`, `SHA-256` $\rightarrow$ `SHA256`).
- `CHECKSUM_MISMATCH` is emitted ONLY when both sides supply the same normalized algorithm for a matched package identity and the digests differ.

### 2.6 License Evidence & Syntactic Comparison
License information preserves SPDX `licenseDeclared`, `licenseConcluded`, `licenseInfoFromFiles`, `NONE`, `NOASSERTION`, and CycloneDX license expressions/choices in `LicenseEvidence`. Comparison is deterministic syntactic/canonical string matching only (no semantic legal equivalence).

### 2.7 Safe Processing Pipeline & Resource Limits
1. Raw byte size check ($\le 5\text{ MiB}$)
2. UTF-8 BOM check & stripping (`b"\xef\xbb\xbf"`)
3. UTF-8 decoding validation
4. JSON-aware structural depth scanner (handles string literals, quotes, escaped characters, max depth 10)
5. JSON parsing (`json.loads`)
6. Typed Pydantic schema validation
7. Package count limit ($\le 5,000$)
8. Bounded extension data validation (depth $\le 5$, keys $\le 50$, array length $\le 100$, string size $\le 16\text{ KiB}$)

### 2.8 Zero Subprocess & Zero Network Execution
All parsing, normalization, and comparison operate in Pure Python with zero external process invocations (`syft`, `cosign`), zero network access, and zero mutable global state.

## 3. Consequences
- Guarantees 100% deterministic, reproducible SBOM comparison output.
- Eliminates false positive `ADDED`/`REMOVED` findings on partial SBOMs.
- Protects the verifier control plane against parser DoS and memory exhaustion attacks.
