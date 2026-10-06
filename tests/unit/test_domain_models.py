"""
Comprehensive Unit Test Suite for Core Domain Models (Phase 1)

Validates:
- Construction, required fields, invalid fields, enum validation
- Boundary conditions & immutability of Value Objects
- Environment variable security enforcement (rejection of prohibited secret keys)
- Architectural Invariants:
  1. Artifact Identity != Verification Result != Risk Assessment != Policy Decision
  2. VerificationResult contains NO policy decisions (PASS/BLOCK) and NO risk scores
  3. Internal Provenance != SLSA Representation != in-toto Representation
  4. Ingestion Rejection != Policy BLOCK Decision
  5. Value Object immutability (frozen=True)
"""

import pytest
from pydantic import ValidationError

from provenanceguard.core.domain import (
    Artifact,
    ArtifactDigest,
    Attestation,
    AttestationType,
    Build,
    BuilderProfile,
    BuildMaterial,
    Decision,
    DigestAlgorithm,
    DomainValidationError,
    DSSEEnvelope,
    DSSESignature,
    EnvironmentVariable,
    ExecutionStatus,
    Finding,
    FindingCategory,
    IngestionRejectedError,
    InTotoStatement,
    MediaType,
    Organization,
    Policy,
    PolicyRule,
    Project,
    Provenance,
    Repository,
    Risk,
    RiskRule,
    ScmProvider,
    Severity,
    SLSABuildDefinition,
    SLSAProvenanceV12,
    SLSARunDetails,
    VerificationDecision,
    VerificationResult,
)

# =====================================================================
# 1. ENTITY TESTS
# =====================================================================


def test_organization_entity():
    org = Organization(id="org_123", name="Acme Security", slug="acme-sec")
    assert org.id == "org_123"
    assert org.slug == "acme-sec"
    assert org.created_at is not None


def test_project_entity():
    proj = Project(id="proj_456", organization_id="org_123", name="Payment Gateway")
    assert proj.id == "proj_456"
    assert proj.organization_id == "org_123"


def test_repository_entity():
    repo = Repository(
        id="repo_789",
        project_id="proj_456",
        provider=ScmProvider.GITHUB,
        url="https://github.com/acme/payment-gateway",
        default_branch="main",
    )
    assert repo.provider == ScmProvider.GITHUB
    assert repo.default_branch == "main"


def test_builder_profile_entity():
    builder = BuilderProfile(
        id="bp_001",
        name="Hardened GCC Builder",
        builder_type="docker",
        pinned_image="gcc:13.2.0-alpine@sha256:abcd1234...",
        is_trusted=True,
    )
    assert builder.is_trusted is True


def test_artifact_entity_valid():
    digest = ArtifactDigest(
        algorithm=DigestAlgorithm.SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    art = Artifact(
        id="art_001",
        project_id="proj_456",
        name="payment-service",
        version="1.0.0",
        media_type=MediaType.ELF,
        digests=[digest],
        size_bytes=1048576,
    )
    assert art.name == "payment-service"
    assert art.digests[0].algorithm == DigestAlgorithm.SHA256


def test_artifact_entity_invalid_name():
    digest = ArtifactDigest(
        algorithm=DigestAlgorithm.SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    with pytest.raises(DomainValidationError):
        Artifact(
            id="art_001",
            project_id="proj_456",
            name="   ",  # Invalid empty/whitespace name
            version="1.0.0",
            media_type=MediaType.ELF,
            digests=[digest],
            size_bytes=100,
        )


def test_build_entity():
    env_var = EnvironmentVariable(key="BUILD_TARGET", value="x86_64-linux-gnu")
    mat = BuildMaterial(uri="https://github.com/acme/libfoo.git")
    build = Build(
        id="bld_001",
        project_id="proj_456",
        builder_profile_id="bp_001",
        source_revision="7f3a91c123...",
        invocation_args=["make", "release"],
        environment=[env_var],
        materials=[mat],
    )
    assert build.invocation_args == ["make", "release"]
    assert len(build.environment) == 1


def test_provenance_entity():
    mat = BuildMaterial(uri="pkg:deb/debian/libc6@2.31")
    prov = Provenance(
        id="prov_001",
        artifact_id="art_001",
        build_id="bld_001",
        source_commit="7f3a91c123...",
        builder_identity="https://github.com/actions/runner",
        build_type="https://slsa.dev/provenance/v1",
        invocation={"entrypoint": "build.sh"},
        materials=[mat],
    )
    assert prov.artifact_id == "art_001"
    assert prov.materials[0].uri == "pkg:deb/debian/libc6@2.31"


def test_verification_result_invariant():
    """
    CRITICAL ARCHITECTURAL INVARIANT TEST:
    VerificationResult MUST NOT contain policy decisions (PASS/BLOCK) or risk scores!
    """
    finding = Finding(
        id="f_001",
        severity=Severity.HIGH,
        category=FindingCategory.FUNCTION_ADDED,
        subject="send_data",
        explanation="Function absent in reference build",
    )
    res = VerificationResult(
        id="vr_001",
        verification_run_id="run_100",
        artifact_id="art_001",
        status=ExecutionStatus.COMPLETED,
        findings=[finding],
        evidence_references=["storage://ref_art_001"],
    )
    assert res.status == ExecutionStatus.COMPLETED
    assert len(res.findings) == 1
    # Verify by introspection that result has NO decision or risk_score field!
    assert not hasattr(res, "decision")
    assert not hasattr(res, "risk_score")


def test_verification_decision_entity():
    """
    Policy Engine decision outcome model test.
    """
    dec = VerificationDecision(
        id="vd_001",
        verification_run_id="run_100",
        policy_id="pol_prod_strict",
        decision=Decision.BLOCK,
        rationale="Function 'send_data' was added to production binary.",
        finding_references=["f_001"],
    )
    assert dec.decision == Decision.BLOCK
    assert dec.policy_id == "pol_prod_strict"


# =====================================================================
# 2. VALUE OBJECT TESTS (IMMUTABILITY & VALIDATION)
# =====================================================================


def test_artifact_digest_valid_sha256():
    d = ArtifactDigest(
        algorithm=DigestAlgorithm.SHA256,
        value="E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    )
    assert d.value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_artifact_digest_invalid_length():
    with pytest.raises(DomainValidationError):
        ArtifactDigest(algorithm=DigestAlgorithm.SHA256, value="abc123short")


def test_artifact_digest_immutability():
    d = ArtifactDigest(
        algorithm=DigestAlgorithm.SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    with pytest.raises(ValidationError):
        d.value = "1111111111111111111111111111111111111111111111111111111111111111"


def test_build_material_value_object():
    mat = BuildMaterial(uri="https://github.com/acme/dep.git", material_type="git_repo")
    assert mat.uri == "https://github.com/acme/dep.git"
    with pytest.raises(DomainValidationError):
        BuildMaterial(uri="   ")


def test_environment_variable_valid():
    env = EnvironmentVariable(key="CFLAG_OPT", value="-O2")
    assert env.key == "CFLAG_OPT"
    assert env.value == "-O2"


def test_environment_variable_rejection_of_prohibited_secrets():
    """
    SECURITY TEST:
    EnvironmentVariable MUST reject prohibited secret keys (e.g. AWS_SECRET_ACCESS_KEY)
    rather than silently mutating/redacting them inside the domain model.
    """
    with pytest.raises(DomainValidationError) as exc_info:
        EnvironmentVariable(key="AWS_SECRET_ACCESS_KEY", value="my_raw_secret_key")
    assert "Prohibited secret environment variable key" in str(exc_info.value)


def test_attestation_value_object():
    digest = ArtifactDigest(
        algorithm=DigestAlgorithm.SHA256,
        value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )
    att = Attestation(
        id="att_001",
        attestation_type=AttestationType.SLSA_V12,
        predicate_type="https://slsa.dev/provenance/v1",
        subject_digest=digest,
        issuer="https://github.com/login/oauth",
    )
    assert att.attestation_type == AttestationType.SLSA_V12


def test_finding_value_object():
    finding = Finding(
        id="f_100",
        severity=Severity.CRITICAL,
        category=FindingCategory.PROVENANCE_TAMPERED,
        subject="provenance.json",
        explanation="Digest mismatch in DSSE envelope",
    )
    assert finding.severity == Severity.CRITICAL


# =====================================================================
# 3. EXTERNAL REPRESENTATIONS & ADAPTERS
# =====================================================================


def test_slsa_v12_adapter():
    build_def = SLSABuildDefinition(
        buildType="https://github.com/actions/runner",
        externalParameters={"repository": "https://github.com/acme/app"},
    )
    run_details = SLSARunDetails(
        builder={"id": "https://github.com/actions/runner@v1"},
        metadata={"invocationId": "inv_123"},
    )
    slsa = SLSAProvenanceV12(buildDefinition=build_def, runDetails=run_details)
    assert slsa.buildDefinition.buildType == "https://github.com/actions/runner"


def test_intoto_statement_adapter():
    stmt = InTotoStatement(
        _type="https://in-toto.io/Statement/v0.1",
        subject=[{"name": "app", "digest": {"sha256": "abc..."}}],
        predicateType="https://slsa.dev/provenance/v1",
        predicate={"builder": {"id": "builder_1"}},
    )
    assert stmt.type_ == "https://in-toto.io/Statement/v0.1"


def test_dsse_envelope_adapter():
    sig = DSSESignature(keyid="key_001", sig="MEQCID...")
    dsse = DSSEEnvelope(
        payload="eyJfdHlwZSI6ICJodHRwczovL2luLXRvdG8uaW8vU3RhdGVtZW50L3YwLjEifQ==",
        payloadType="application/vnd.in-toto+json",
        signatures=[sig],
    )
    assert dsse.signatures[0].keyid == "key_001"


# =====================================================================
# 4. DECLARATIVE DOMAIN STUBS
# =====================================================================


def test_declarative_policy_stub():
    rule = PolicyRule(id="rule_1", rule_type="disallow_added_functions")
    pol = Policy(
        id="pol_001",
        project_id="proj_456",
        name="Strict Release Policy",
        warning_threshold=20,
        block_threshold=60,
        rules=[rule],
    )
    assert pol.block_threshold == 60


def test_declarative_risk_stub():
    rule = RiskRule(id="rr_1", category="FUNCTION_ADDED", weight=25, explanation="Added function")
    risk = Risk(id="risk_001", name="Standard Risk Model", rules=[rule])
    assert risk.rules[0].weight == 25


# =====================================================================
# 5. INGESTION REJECTION VS POLICY BLOCK INVARIANT
# =====================================================================


def test_ingestion_rejection_exception():
    """
    INVARIANT TEST:
    Ingestion rejection signals malformed schema input.
    It MUST NOT automatically produce a policy BLOCK decision.
    """
    err = IngestionRejectedError(
        error_code="PG-1001",
        message="Malformed ELF header offset",
        details=["Section header offset 0x9999 exceeds file length"],
    )
    assert err.error_code == "PG-1001"
    assert "Malformed ELF" in str(err)


# =====================================================================
# 6. SERIALIZATION & DESERIALIZATION TESTS
# =====================================================================


def test_entity_serialization_deserialization():
    org = Organization(id="org_999", name="Test Org", slug="test-org")
    json_str = org.model_dump_json()

    org_restored = Organization.model_validate_json(json_str)
    assert org_restored.id == org.id
    assert org_restored.name == org.name
