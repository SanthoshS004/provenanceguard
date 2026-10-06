# ADR-011: Artifact Comparison Engine Architecture & Evidence Boundary

- **Status**: Accepted
- **Deciders**: Principal Architect, Security Architect, Core Platform Team
- **Date**: 2026-09-05

## Context

Phase 4 of ProvenanceGuard establishes static comparison between reference artifacts (built independently from clean source commits) and target artifacts (submitted from production CI/CD).

The verifier must evaluate whole-file, section, function code, and structural deltas while maintaining strict evidence/decision boundaries, memory bounds, function range safety, inventory completeness handling, and payload determinism.

## Decision

1. **`BoundedArtifactReader` Subsystem**:
   - Resides under `core/verification/artifact_reader.py`.
   - Read-only stream wrapper operating on trusted file handles/paths. Never executes binaries, loads full multi-gigabyte files into RAM, or invokes shell commands (`readelf`/`objdump`).
   - Validates `authoritative_digest` whole-file SHA-256 upon instantiation (raising `AuthoritativeDigestMismatchError` on mismatch).
   - Enforces non-negative bounds, read size caps (10 MB), and file size boundaries.

2. **Separation of Identity vs. Byte Code Fingerprinting**:
   - `SectionMatchKey(name, section_type)` is the primary section identity. Secondary rename correlation uses `(section_type, flags, size, section_digest)` and requires EXACTLY ONE candidate to emit `SECTION_RENAMED`.
   - `FunctionMatchKey(name, section_name, binding)` is the function identity key. `FunctionCodeDigest` is computed as the raw SHA-256 of function byte range `[offset : offset + size]` via `BoundedArtifactReader`.
   - Zero-size functions (`size == 0`) do not calculate code digests or hash empty byte streams.

3. **Function Inventory Completeness & Non-Negative Findings**:
   - Represented explicitly as `FunctionInventoryCompleteness` (`COMPLETE`, `PARTIAL`, `UNAVAILABLE`).
   - Stripped binaries with `.dynsym` only or reports marked `is_truncated = True` have `PARTIAL` completeness (`is_partial_comparison = True`).
   - Under `PARTIAL` or `UNAVAILABLE` completeness, missing symbols MUST NOT produce negative findings such as `REMOVED_FUNCTION`.

4. **Payload Determinism & Evidence Boundary**:
   - `ComparisonResult` contains 0 policy decision fields (`PASS`/`BLOCK`), 0 risk scores, and 0 execution timestamps (timestamps isolated in `ComparisonExecutionMetadata`).
   - All delta lists in `ComparisonResult` are deterministically sorted prior to serialization (`sort_deltas()`).

5. **Granular W+X Evidence & Compatibility Errors**:
   - Section vs. load segment permission changes tracked separately (`WX_SECTION_INTRODUCED`, `WX_LOAD_SEGMENT_INTRODUCED`, `SECTION_PERMISSION_CHANGED`, `SEGMENT_PERMISSION_CHANGED`).
   - Mismatches in `e_class`, `endianness`, or raw `e_machine` raise `ELFCompatibilityError` (`PG-4001`).
   - Incompatible media types raise `IncompatibleArtifactTypeError` (`PG-4002`).

## Consequences

- Objective, deterministic evidence is produced for policy engines in later phases.
- Zero-day parser exploitation and arbitrary shell command execution risks are eliminated.
- Stripped binaries and partial analyses degrade gracefully without false negative alerts.
