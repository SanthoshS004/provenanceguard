# ProvenanceGuard Known System Boundaries & Technical Limitations

This document explicitly defines the boundaries, known technical limitations, and non-goals of ProvenanceGuard.

---

## 1. Primary Security Limitations

### 1.1 Compromised Compiler / Toolchain (Trusting Trust / T9)
- **Limitation**: ProvenanceGuard **DOES NOT** detect a Ken Thompson "Trusting Trust" attack if both the production build (`Domain B`) and the independent reference builder (`Domain D`) execute compilation using the exact same compromised compiler binary.
- **Bound**: Binary machine code comparison will show `EXACT_MATCH` because both environments execute identical backdoor compiler passes. Detection is only possible if Domain D utilizes an independently bootstrapped compiler toolchain (e.g. GCC built from source using an isolated toolchain).

### 1.2 Signature Validity vs Software Safety (T6 Boundary)
- **Limitation**: A cryptographically valid signature (`Cosign`/`Sigstore`) indicates **signer authorization**, NOT **software safety**.
- **Bound**: If an attacker steals an authorized developer's Cosign key or OIDC token, they can produce a valid signature on a malicious binary. ProvenanceGuard mitigates this by requiring multi-dimensional policy checks (signature + provenance + binary comparison + SBOM inventory).

### 1.3 Non-Reproducible Binary Build Variance
- **Limitation**: Many modern compilers generate non-reproducible binary variance due to build paths, compiler timestamps, random symbol names, embedded build-IDs, or debug sections (`.comment`, `.note.gnu.build-id`).
- **Bound**: ProvenanceGuard does not expect raw byte-for-byte binary equality on all builds. It performs structural function extraction and disassembly normalization. Non-reproducible metadata differences generate `PASS_WITH_WARNING` or `WARNING` findings rather than hard `BLOCK` decisions, unless policy enforces strict byte-level reproducibility (`require_exact_byte_match: true`).

### 1.4 Stripped Binaries
- **Limitation**: If an ELF binary is stripped (`strip --strip-all`), symbol table entries (`.symtab`, `.strtab`) are removed.
- **Bound**: Function-level identity matching based on normalized function names is not possible. ProvenanceGuard falls back to section-level diffing, entry point analysis, dynamic import inspection (`.dynsym`), and byte chunk heuristic analysis.

---

## 2. Dynamic vs Static Analysis Boundaries

- **Static Verification Only**: ProvenanceGuard performs static binary, provenance, signature, and SBOM analysis. It **DOES NOT** execute runtime sandbox dynamic analysis (e.g., executing the binary in a Windows/Linux sandbox to observe C2 network calls).
- **Static Analysis Obfuscation**: Highly obfuscated binaries (e.g., custom runtime packers, polymorphic code engines, anti-disassembly tricks) may fail structural disassembly or yield `UNANALYZABLE` function regions.

---

## 3. Dependency Inventory Boundaries

- **Un-declared Dependencies**: SBOM analysis relies on declared package inventories (SPDX/CycloneDX) and dynamic library imports (`DT_NEEDED` in ELF headers). If an attacker statically links a malicious library directly into a custom C file without updating the build manifest or dynamic symbol table, SBOM comparison will not detect the missing dependency unless binary function diffing flags the added function.

---

## 4. Operational Boundaries

- **Phase 0 Status**: The repository is currently in Phase 0 (Architecture & Foundation Scaffolding). All production verification components are scaffolded and require Phase 1–20 implementation prior to enterprise deployment.
