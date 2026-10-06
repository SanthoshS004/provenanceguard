# ProvenanceGuard Attack Trees Analysis

This document details attack trees targeting the software release pipeline, demonstrating how ProvenanceGuard mitigates each attack path.

---

## 1. Primary Goal: "Cause a Malicious Software Artifact to Reach Production"

```
                                [ GOAL: Deploy Malicious Artifact to Production ]
                                                        │
    ┌───────────────────┬───────────────────┬───────────┴───────┬───────────────────┬───────────────────┐
    │                   │                   │                   │                   │                   │
    ▼                   ▼                   ▼                   ▼                   ▼                   ▼
[Branch 1:           [Branch 2:          [Branch 3:          [Branch 4:          [Branch 5:          [Branch 6:
Compromise CI]       Modify Build]       Compromise Dep]     Replace Artifact]   Forge Provenance]   Bypass Verifier]
    │                   │                   │                   │                   │                   │
    ├─ Inject code      ├─ Tweak flags      ├─ Typosquatting    ├─ Swapped binary   ├─ Craft fake JSON  ├─ Exploit API
    └─ Backdoor ELF     └─ Add backdoor     └─ Dep confusion    └─ MITM registry    └─ Forge DSSE       └─ Alter policy
```

---

## 2. Detailed Attack Path & Mitigation Analysis

### Branch 1: Compromise Production CI Runner
- **Sub-Goal 1.1**: Gain shell execution on CI build node (Domain B).
- **Sub-Goal 1.2**: Inject backdoor functions (`send_data()`) into release ELF binary after compilation.
- **Attack Path**: CI script runs -> compilation produces `app.o` -> post-build step appends `malicious.o` -> links into `app`.
- **ProvenanceGuard Mitigation**:
  - **Independent Builder (`Domain D`)**: Triggers reference build from clean SCM commit SHA.
  - **Binary Function Comparison**: Detects `NEW_FUNCTION` or `FUNCTION_CODE_CHANGED`.
  - **Decision**: `BLOCK` (Risk score > 70).

---

### Branch 2: Modify Build Script in SCM Repository
- **Sub-Goal 2.1**: Compromise developer credentials or submit un-reviewed Pull Request modifying `Makefile` / `build.sh`.
- **Sub-Goal 2.2**: Add compiler flags `-DENABLE_BACKDOOR=1` or link unapproved internal libraries.
- **ProvenanceGuard Mitigation**:
  - **SLSA Provenance Inspection**: Inspects SLSA v1.2 provenance predicates (`buildDefinition`, `invocation.parameters`).
  - **Policy Rules**: Evaluates policy `fail_on_unexpected_imports: true` and verifies build invocation against signed baseline templates.
  - **Decision**: `BLOCK` or `PASS_WITH_WARNING` depending on policy strictness.

---

### Branch 3: Dependency Substitution (Supply Chain Poisoning)
- **Sub-Goal 3.1**: Publish malicious package `lib-auth-v2` to public PyPI/NPM registry with same name as private internal package.
- **Sub-Goal 3.2**: Production build pulls public malicious dependency during build.
- **ProvenanceGuard Mitigation**:
  - **SBOM Inventory Comparison**: Parses SPDX / CycloneDX SBOM, comparing production dependency tree against reference build inventory.
  - **Finding**: Flags `UNEXPECTED_DEPENDENCY` and `DEPENDENCY_DIGEST_MISMATCH`.
  - **Decision**: `BLOCK`.

---

### Branch 4: Artifact Replacement Post-Build
- **Sub-Goal 4.1**: Intercept or compromise artifact release registry post-CI run, replacing legitimate binary `payment-service-v1` with backdoored version.
- **ProvenanceGuard Mitigation**:
  - **Cryptographic Digest Cross-Reference**: Production artifact SHA-256 digest differs from provenance statement hash and reference build hash.
  - **Finding**: `DIGEST_MISMATCH`.
  - **Decision**: Immediate `BLOCK`.

---

### Branch 5: Forge Provenance Attestation
- **Sub-Goal 5.1**: Hand-craft a fake SLSA JSON provenance file claiming an unauthorized artifact came from main Git branch.
- **ProvenanceGuard Mitigation**:
  - **in-toto DSSE Envelope Verification**: Verifies DSSE digital signature on provenance attestation envelope.
  - **Sigstore / Fulcio Verification**: Validates OIDC issuer and workflow identity certificate.
  - **Finding**: `PROVENANCE_SIGNATURE_INVALID` or `BUILDER_IDENTITY_UNTRUSTED`.
  - **Decision**: `BLOCK`.

---

### Branch 6: Bypass Verifier or Compromise Control Plane
- **Sub-Goal 6.1**: Exploit API vulnerability to tamper with verification decision, or modify policy YAML stored in database.
- **ProvenanceGuard Mitigation**:
  - **Zero-Trust Control Plane Isolation (`Domain C`)**: Control plane is network-segregated from production CI. Production CI can only post verification runs; it cannot alter verifier policy or edit database records.
  - **Immutable Audit Logging**: Every policy change or decision override is recorded in an immutable PostgreSQL audit trail (`audit_logs`).
