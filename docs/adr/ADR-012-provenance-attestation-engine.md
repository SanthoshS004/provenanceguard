# ADR-012: Attestation Verification & Provenance Evidence Engine Architecture

## Status
Approved

## Context
ProvenanceGuard requires a secure, deterministic, pure-Python attestation verification engine capable of validating in-toto Statement v1, SLSA v1.2 provenance statements, DSSE envelopes, and Sigstore bundles (Fulcio X.509 chains and Rekor transparency log entries). The verification engine must enforce a strict evidence-only boundary without leaking organizational policy decisions (`PASS`/`BLOCK`/`trusted`/`untrusted`) or risk scores into evidence domain models.

## Decision

1. **Deterministic DSSE Key-ID Selection Semantics**: `DSSEVerifier` enforces explicit key-ID matching logic. Matching key ID verifies using that exact `VerificationKey`. Absent key ID filters candidate keys to eligible candidates matching the signature algorithm profile; if exactly 1 succeeds, verification succeeds and records key ID with an absent keyid warning; if 0 or >1 candidates succeed, raises `DSSEVerificationError` (`PG-5001`). Unknown key IDs or key conflicts raise `PG-5001`.
2. **Fulcio Root Certificates as Trust Anchors ONLY**: Configured Fulcio roots in `fulcio_root_certificates` are trusted configuration material. Candidate paths build from leaf to bundle-supplied intermediates (untrusted) to configured roots. Leaf public key is extracted for keyless DSSE signature verification ONLY AFTER path validation succeeds.
3. **Execution Separation**: Pure Python execution using standard `cryptography` library for signature verification, public-key operations, and X.509 parsing/validation, and a dedicated RFC 8785-compatible JCS implementation (`rfc8785`) for deterministic JSON canonicalization.
4. **Rekor SET Verification Flow**: Canonicalizes Rekor entry document with `verification` object removed using RFC 8785 JCS, verifying `signedEntryTimestamp` and binding `logID`, `logIndex`, `body`, and `integratedTime`.
5. **Rekor Merkle Inclusion-Proof Binding**: Authenticates checkpoint signature, verifies checkpoint log identity, enforces `inclusionProof.logIndex == expected Rekor entry logIndex`, verifies tree-size and Merkle root hash equality. Sets `rekor_inclusion_proof_verified = True`.
6. **Known vs Open-Ended vs Unknown Fields**: Known SLSA fields are strongly typed; known open-ended parameters (`externalParameters`, `internalParameters`) are typed as `JsonValue`; unknown protocol fields are structurally preserved as `extension_evidence: Dict[str, JsonValue]` at their original structural location without affecting policy decisions or being silently discarded.
7. **Location-Preserved Extension Evidence**: Unknown SLSA extension fields are preserved at their structural location (e.g. subject-level extensions in `SubjectEvidence.extension_evidence`).
8. **Known Field Type Safety**: Malformed known fields raise `ProvenanceValidationError` (`PG-5002`). Unknown fields do not alter policy or trust verdicts.
9. **Elimination of Broad `Any`**: Evidence domain models use the strongly typed recursive `JsonValue` abstraction (`Union[None, bool, int, float, str, List[JsonValue], Dict[str, JsonValue]]`).
10. **Subject Correlation Cardinality**: Preserves all matching subjects in `matched_subjects` without arbitrary selection. `subject_digest_match = True` ONLY when `matching_subject_count == 1`. Zero matches set `ZERO_SUBJECT_MATCH` and `subject_digest_match = False` as objective evidence.
11. **Explicit Cryptographic Algorithm Profiles**: Supported algorithm profiles: `ED25519`, `ECDSA_P256_SHA256`, `RSA_PSS_SHA256`, `RSA_PKCS1_SHA256`.
12. **Sigstore Keyless Verification**: Validated Fulcio leaf public key used for keyless DSSE verification.
13. **Elimination of Generic Trust Terminology**: Generic terms `trust_status`, `TRUSTED`, `UNTRUSTED` are strictly omitted. Replaced with `verification_state` (`CRYPTOGRAPHICALLY_VERIFIED`, `OBSERVED_ONLY`, `UNAVAILABLE`) and `rekor_integrated_time_cryptographically_verified: bool`.
14. **Deterministic Certificate-Time Evaluation**: Injected `VerificationContext.evaluation_time` input eliminates direct system clock calls (`datetime.now()`, `time.time()`).
15. **Preservation of All SAN URIs**: `san_uris_observed: List[str]` records all SAN URIs from certificate extensions without arbitrary truncation or selection.
16. **Objective Evidence Boundary**: Zero subject match or unexpected identity is recorded as objective evidence without converting to policy verdicts.
17. **DSSE Exact-Byte PAE**: Pre-Authentication Encoding uses exact ASCII decimal length representations and exact raw payload bytes without JSON reserialization.
18. **Multi-Sig vs Single-Sig Cardinality**: Generic `DSSEVerifier` supports multi-signature envelopes; `SigstoreVerifier` requires **exactly 1** DSSE signature.
19. **Payload SHA-256 Storage**: Evidence reports store `payload_sha256` and `decoded_payload_size`; raw payload bytes are omitted to optimize report size.
20. **Sigstore Bundle Formats**: Primary support for `v0.3` (`application/vnd.dev.sigstore.bundle.v0.3+json`), with legacy `v0.2`/`v0.1` adapters.
21. **Explicit X.509 Path Validation**: Validates signatures, validity periods, basic constraints, path constraints, key usage (`digitalSignature`), and EKU (`code signing`).
22. **Adversarial Test Suite**: Full offline test coverage across malformed base64, signature tampering, key-ID ambiguity, certificate chain attacks, Rekor SET tampering, logIndex mismatch, Merkle proof attacks, and boundary limits.
23. **Bounded Resource Limits**: Enforces hard caps on envelope size (2 MB), payload size (1 MB), payloadType size (256 B), signature count (32), signature size (4 KB), subjects (128), resolvedDependencies (1000), byproducts (1000), JSON nesting depth (32), cert chain length (10), and bundle size (5 MB).
24. **Structural Validation vs Policy Separation**: Structural schema validity is separated from organization-specific release policy evaluation.

## Consequences
Verification reports contain 0 release verdicts (`PASS`/`BLOCK`) and 0 risk scores. All verification flows run in pure Python without external CLI subprocesses or network dependencies.
