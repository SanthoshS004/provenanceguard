# ADR-003: Generic Artifact Abstraction & Pluggable Analyzer Protocol

- **Status**: ACCEPTED
- **Date**: 2026-09-04
- **Authors**: Core Development Team

## 1. Context
ProvenanceGuard initially focuses on Linux ELF binaries and OCI container images, but must support future artifact types (PE binaries, JAR files, WebAssembly modules) without modifying core verification logic.

## 2. Problem
Hardcoding ELF-specific structures into core domain models creates tight coupling and prevents extensible multi-format security checks.

## 3. Decision
Define a generic `Artifact` abstraction and an extensible Python `ArtifactAnalyzer` protocol exposing:
- `supports(media_type: str) -> bool`
- `analyze(artifact_path: Path) -> AnalyzerResult`
- `validate(metadata: dict) -> bool`
- `capabilities() -> AnalyzerCapabilities`

Specific analyzers (`ELFAnalyzer`, `OCIAnalyzer`, `SBOMAnalyzer`) implement this contract and register dynamically.

## 4. Alternatives Considered
- **Direct C Binding Monolith**: Fast, but difficult to maintain and test across diverse artifact schemas.

## 5. Security Consequences
- New artifact parsers can be developed and isolated independently without altering core security policy code.

## 6. Operational Consequences
- Unified JSON reporting schema across all artifact analysis types.

## 7. Future Reconsideration Conditions
- Re-evaluate if memory-efficient C-native analyzer extensions are needed for multi-gigabyte PE/JAR binaries.
