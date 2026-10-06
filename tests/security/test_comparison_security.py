"""
Security Boundary Tests for Phase 4 Artifact Comparison Engine
Verifies that ComparisonResult contains ZERO policy verdicts, risk scores, or execution decisions.
"""

import io

from provenanceguard.analyzers.elf.models import ELFAnalysisReport, ELFHeaderInfo, ELFSectionInfo
from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.comparison import ArtifactComparator


def test_comparison_result_evidence_only():
    """
    Verifies that ComparisonResult contains objective evidence ONLY.
    Must not contain PASS, BLOCK, SAFE, MALICIOUS, risk_score, or decision fields.
    """
    h = ELFHeaderInfo(
        e_class=2,
        class_name="ELF64",
        endianness="little",
        e_machine=62,
        architecture_name="x86_64",
        entry_point=0x400000,
        e_phoff=64,
        e_shoff=120,
        e_flags=0,
        e_ehsize=64,
        e_phentsize=56,
        e_phnum=1,
        e_shentsize=64,
        e_shnum=1,
        e_shstrndx=0,
    )
    sec = ELFSectionInfo(
        index=0,
        name=".text",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=6,
        is_alloc=True,
        is_write=False,
        is_exec=True,
        address=0,
        offset=0,
        size=10,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="digest_abc",
    )
    report = ELFAnalysisReport(
        header=h,
        program_headers=[],
        sections=[sec],
        all_symbols=[],
        imported_libraries=["libc.so.6"],
        symbol_derived_functions=[],
        has_wx_sections=False,
        has_wx_load_segments=False,
        is_stripped=False,
        is_truncated=False,
    )

    r1_stream = io.BytesIO(b"0" * 50)
    r2_stream = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(r1_stream) as r1, BoundedArtifactReader(r2_stream) as r2:
        result = ArtifactComparator.compare_elf_artifacts(
            reference_report=report,
            target_report=report,
            reference_reader=r1,
            target_reader=r2,
            reference_digest="sha256_ref",
            target_digest="sha256_target",
        )

    dump = result.model_dump()

    # Forbidden policy/decision/risk keys
    forbidden_keys = {
        "verdict",
        "decision",
        "risk_score",
        "risk_level",
        "pass_or_block",
        "is_safe",
        "policy_eval",
    }
    for key in forbidden_keys:
        assert key not in dump, f"Forbidden policy key '{key}' found in ComparisonResult payload!"

    # Verify no string field contains policy verdicts
    json_str = result.model_dump_json()
    assert '"PASS"' not in json_str
    assert '"BLOCK"' not in json_str
    assert '"SAFE"' not in json_str
    assert '"MALICIOUS"' not in json_str
