# ProvenanceGuard Threat Model Specification

This document defines the primary threat model for ProvenanceGuard. It analyzes threats **T1 through T9**, identifying attack vectors, trust boundaries crossed, impact, detection capabilities, mitigations, residual risk, and explicit system limitations.

---

## 1. Threat Inventory Matrix

| ID | Threat Name | Primary Attacker | Impact Level | Trust Boundary Crossed |
|---|---|---|---|---|
| **T1** | Compromised CI Runner | External / Lateral Movement | High | Domain B → Domain F |
| **T2** | Modified Build Script | Malicious Developer / PR Hijack | High | Domain A → Domain B |
| **T3** | Dependency Substitution | Supply Chain Attacker | Critical | Domain B → Domain F |
| **T4** | Artifact Replacement | Network / Registry Attacker | Critical | Domain B → Domain F |
| **T5** | Provenance Forgery | Compromised CI Service Account | High | Domain B → Domain C |
| **T6** | Signing Key Compromise | Insider / Credential Theft | Critical | Domain B → Domain C |
| **T7** | Malicious Insider | Authorized Employee | High | Domain A/B → Domain F |
| **T8** | ProvenanceGuard Compromise | Advanced Targeted Attacker | Critical | Domain C Control Plane |
| **T9** | Compromised Compiler/Toolchain | Nation-State / Advanced | Critical | Domain B / Domain D |

---

## 2. Detailed Threat Analysis

### T1 — Compromised CI Runner
- **Attacker**: External adversary who gains shell/root access on a production CI worker (Domain B).
- **Asset**: Production binaries, release artifacts, release pipeline integrity.
- **Attack Path**: Attacker hooks into the build pipeline or post-build step, injecting malicious code or backdoor functions into the compiled binary before artifact upload.
- **Trust Boundary Crossed**: Domain B (Untrusted CI) → Domain F (Artifact Storage).
- **Impact**: Unverified malicious binary is published to production registries.
- **Detection Capability**: **HIGH**. ProvenanceGuard compares the production artifact against an independently generated reference build (Domain D). Binary function analysis flags `NEW_FUNCTION` or `FUNCTION_CODE_CHANGED`.
- **Prevention/Control**: Block CI release pipeline on verification mismatch (`BLOCK`).
- **Residual Risk**: Non-reproducible build noise may require threshold tuning.
- **Limitations**: Requires an isolated reference build environment (Domain D).

---

### T2 — Modified Build Script
- **Attacker**: Malicious contributor or compromised developer account modifying `Makefile`, `build.sh`, or CI YAML files.
- **Asset**: Build flags, compiler optimization, imported dependencies.
- **Attack Path**: Attacker alters build parameters (e.g. adding `-DDEBUG_BACKDOOR`) or changing compiler flags in SCM repository.
- **Trust Boundary Crossed**: Domain A (SCM) → Domain B (Production Build).
- **Impact**: Binary produced has security controls disabled or malicious flags enabled.
- **Detection Capability**: **HIGH**. ProvenanceGuard inspects SLSA v1.2 provenance predicates (`buildDefinition`, `invocation.parameters`) and compares independent build output against production build output.
- **Prevention/Control**: Policy rules requiring verified SLSA provenance matching approved build templates.
- **Residual Risk**: If the build script change is merged into main source branch, independent builder will also execute the modified script unless policy inspects PR diff boundaries.

---

### T3 — Dependency Substitution (Typosquatting / Dependency Confusion)
- **Attacker**: Supply chain attacker publishing malicious packages to public registries.
- **Asset**: Software component inventory, transitive dependencies.
- **Attack Path**: Production build pulls a malicious upstream library instead of the approved internal dependency.
- **Trust Boundary Crossed**: Domain B → Domain F.
- **Impact**: Malicious code executed during runtime.
- **Detection Capability**: **HIGH**. ProvenanceGuard compares expected SBOM inventory (SPDX/CycloneDX) and ELF dynamic imports/section hashes against reference build inventory.
- **Prevention/Control**: Flags `UNEXPECTED_DEPENDENCY` or `DEPENDENCY_DIGEST_MISMATCH`.
- **Residual Risk**: Obfuscated sub-dependencies not captured in lockfiles.

---

### T4 — Artifact Replacement (In-Flight / Registry Tampering)
- **Attacker**: Man-in-the-middle attacker or compromised registry user replacing artifact files post-build.
- **Asset**: Production release binary.
- **Attack Path**: Legitimate build completes, but the artifact stored in the release registry is swapped with a malicious payload.
- **Trust Boundary Crossed**: Domain B → Domain F.
- **Impact**: Unchecked deployment of malicious binary.
- **Detection Capability**: **CRITICAL/HIGH**. Cryptographic digest (SHA-256) mismatch between SCM provenance records and actual uploaded artifact.
- **Prevention/Control**: Immediate `BLOCK` due to `DIGEST_MISMATCH`.

---

### T5 — Provenance Forgery / Metadata Modification
- **Attacker**: Compromised CI script attempting to craft fake SLSA provenance statements.
- **Asset**: Provenance attestations, in-toto metadata.
- **Attack Path**: Attacker uploads a backdoored artifact along with a hand-crafted provenance JSON claiming it was built from a clean commit.
- **Trust Boundary Crossed**: Domain B → Domain C.
- **Impact**: Verifier tricked into trusting an unauthorized build.
- **Detection Capability**: **HIGH**. ProvenanceGuard verifies in-toto DSSE envelopes, builder identity certificates via Sigstore Fulcio/Rekor, and cross-references SCM commit SHAs.
- **Prevention/Control**: Signature validation on provenance attestation DSSE envelope.

---

### T6 — Signing Credential / Key Compromise
- **Attacker**: Attacker steals an authorized Cosign private key or OIDC token.
- **Asset**: Cryptographic signing authority.
- **Attack Path**: Attacker signs a malicious artifact with a valid corporate key.
- **Trust Boundary Crossed**: Domain B → Domain C.
- **Impact**: Artifact carries a cryptographically valid signature.
- **Detection Capability**: **HIGH**. ProvenanceGuard operates on zero-trust principle: **Signature Valid ≠ Software Safe**. Binary diffing, SBOM comparison, and independent build matching will still detect the anomaly despite the valid signature.
- **Prevention/Control**: Policy engine evaluates multi-dimensional evidence (signature + provenance + binary comparison).

---

### T7 — Malicious Insider
- **Attacker**: Rogue developer with commit and release permissions.
- **Asset**: Source code repository, release pipeline.
- **Attack Path**: Developer commits malicious source code directly to main repository branch.
- **Trust Boundary Crossed**: Domain A → Domain B → Domain F.
- **Impact**: Malicious code included in clean build.
- **Detection Capability**: **MEDIUM/LOW** (Binary diffing will show match since independent builder builds the same malicious commit).
- **Prevention/Control**: Mitigated via policy checks requiring multi-party code review (SLSA Source controls), commit signing validation, and static security rule policy gates.
- **Residual Risk**: Code-level backdoors require SAST/code review integration.

---

### T8 — ProvenanceGuard Control Plane / Verifier Compromise
- **Attacker**: Adversary attacking ProvenanceGuard API, Worker, or Database directly.
- **Asset**: Verification decisions, audit logs, policy rules.
- **Attack Path**: Exploiting a vulnerability in ProvenanceGuard API or un-sandboxed worker parser.
- **Trust Boundary Crossed**: Untrusted Input → Domain C Control Plane.
- **Impact**: Decision tampering, bypass of release gate.
- **Prevention/Control**:
  - Worker processes run in ephemeral, unprivileged Docker containers (`Domain E`) with strict RAM/CPU limits.
  - Strict input sanitization on all uploaded ELF binaries, JSON metadata, and archive files.
  - Read-only storage for audit logs; immutable PostgreSQL audit records.

---

### T9 — Compromised Compiler / Toolchain (Ken Thompson / Trusting Trust Attack)
- **Attacker**: Nation-state adversary compromising GCC/Clang compiler binary on build host.
- **Asset**: Compilation toolchain.
- **Attack Path**: Compiler injects backdoor code during compilation whenever specific source patterns are recognized, without altering source files.
- **Trust Boundary Crossed**: Domain B / Domain D Compiler → Binary Output.
- **Impact**: Both production build and reference build contain identical malicious machine code if they share the compromised compiler.
- **Detection Capability**: **LIMITATION (LOW)**.
- **Explicit Security Claim**: **ProvenanceGuard DOES NOT solve Trusting-Trust attacks if both production and independent builders share the exact same compromised compiler binary**. If Domain D uses a clean, independently bootstrapped compiler toolchain, ProvenanceGuard will detect the machine code discrepancy.
