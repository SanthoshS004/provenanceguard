"""
Unit Tests for Artifact Comparison Engine (Phase 4)
"""

import io

import pytest

from provenanceguard.analyzers.elf.models import (
    ELFAnalysisReport,
    ELFHeaderInfo,
    ELFSectionInfo,
    ELFSegmentInfo,
    ELFSymbolInfo,
)
from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.comparison import ArtifactComparator
from provenanceguard.core.verification.exceptions import (
    ELFCompatibilityError,
    IncompatibleArtifactTypeError,
)
from provenanceguard.core.verification.models import FunctionInventoryCompleteness


def make_mock_elf_report(
    e_class: int = 2,
    endianness: str = "little",
    e_machine: int = 62,
    sections=None,
    symbols=None,
    imported_libraries=None,
    has_wx_sections: bool = False,
    has_wx_load_segments: bool = False,
    is_stripped: bool = False,
    is_truncated: bool = False,
) -> ELFAnalysisReport:
    """Helper creating mock ELFAnalysisReport for testing."""
    header = ELFHeaderInfo(
        e_class=e_class,
        class_name="ELF64" if e_class == 2 else "ELF32",
        endianness=endianness,
        e_machine=e_machine,
        architecture_name="x86_64" if e_machine == 62 else "i386",
        entry_point=0x400000,
        e_phoff=64,
        e_shoff=120,
        e_flags=0,
        e_ehsize=64 if e_class == 2 else 52,
        e_phentsize=56 if e_class == 2 else 32,
        e_phnum=1,
        e_shentsize=64 if e_class == 2 else 40,
        e_shnum=len(sections or []),
        e_shstrndx=0,
    )
    return ELFAnalysisReport(
        header=header,
        program_headers=[
            ELFSegmentInfo(
                index=0,
                segment_type=1,
                segment_type_name="PT_LOAD",
                flags=3 if has_wx_load_segments else 5,
                is_read=True,
                is_write=has_wx_load_segments,
                is_exec=True,
                offset=0,
                vaddr=0x400000,
                paddr=0x400000,
                filesz=256,
                memsz=256,
                align=4096,
            )
        ],
        sections=sections or [],
        all_symbols=symbols or [],
        imported_libraries=imported_libraries or ["libc.so.6"],
        symbol_derived_functions=[
            s for s in (symbols or []) if getattr(s, "symbol_type", "") == "STT_FUNC"
        ],
        has_wx_sections=has_wx_sections,
        has_wx_load_segments=has_wx_load_segments,
        is_stripped=is_stripped,
        is_truncated=is_truncated,
    )


# --- Scenario 1: Identical Artifacts ---
def test_identical_artifacts_zero_deltas():
    content = b"ELF_BINARY_CONTENT_DUMMY_DATA_12345"
    ref_stream = io.BytesIO(content)
    target_stream = io.BytesIO(content)

    sec = ELFSectionInfo(
        index=0,
        name=".text",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=6,
        is_alloc=True,
        is_write=False,
        is_exec=True,
        address=0x400000,
        offset=0,
        size=10,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="abc123digest",
    )
    sym = ELFSymbolInfo(
        name="main",
        symbol_type="STT_FUNC",
        binding="STB_GLOBAL",
        visibility="STV_DEFAULT",
        section_index=0,
        section_name=".text",
        address=0x400000,
        size=10,
        offset=0,
    )

    report = make_mock_elf_report(sections=[sec], symbols=[sym])

    with (
        BoundedArtifactReader(ref_stream) as ref_r,
        BoundedArtifactReader(target_stream) as target_r,
    ):
        res = ArtifactComparator.compare_elf_artifacts(
            reference_report=report,
            target_report=report,
            reference_reader=ref_r,
            target_reader=target_r,
            reference_digest="digest_sha256_identical",
            target_digest="digest_sha256_identical",
        )

    assert res.digest_matches is True
    assert res.reference_completeness == FunctionInventoryCompleteness.COMPLETE
    assert res.target_completeness == FunctionInventoryCompleteness.COMPLETE
    assert res.is_partial_comparison is False
    assert len(res.structural_deltas) == 0
    assert len(res.function_deltas) == 0
    assert len(res.dependency_deltas) == 0
    assert len(res.security_observation_deltas) == 0


# --- Scenario 2: Section Modifications ---
def test_section_added_and_removed():
    ref_sec = ELFSectionInfo(
        index=0,
        name=".text",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=6,
        is_alloc=True,
        is_write=False,
        is_exec=True,
        address=0x400,
        offset=0,
        size=10,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="ref_digest_text",
    )
    target_sec_new = ELFSectionInfo(
        index=0,
        name=".rodata",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=2,
        is_alloc=True,
        is_write=False,
        is_exec=False,
        address=0x500,
        offset=0,
        size=20,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="target_digest_rodata",
    )

    ref_report = make_mock_elf_report(sections=[ref_sec])
    target_report = make_mock_elf_report(sections=[target_sec_new])

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        res = ArtifactComparator.compare_elf_artifacts(
            ref_report, target_report, r1, r2, "sha_ref", "sha_target"
        )

    assert res.digest_matches is False
    delta_types = [d.delta_type for d in res.structural_deltas]
    assert "SECTION_REMOVED" in delta_types
    assert "SECTION_ADDED" in delta_types


# --- Scenario 3: Section Rename Correlation ---
def test_section_renamed_deterministic():
    # Same section_type (1), flags (6), size (20), content_digest ("same_digest")
    ref_sec = ELFSectionInfo(
        index=0,
        name=".text_old",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=6,
        is_alloc=True,
        is_write=False,
        is_exec=True,
        address=0x400,
        offset=0,
        size=20,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="same_digest",
    )
    target_sec = ELFSectionInfo(
        index=0,
        name=".text_new",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=6,
        is_alloc=True,
        is_write=False,
        is_exec=True,
        address=0x400,
        offset=0,
        size=20,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="same_digest",
    )

    ref_report = make_mock_elf_report(sections=[ref_sec])
    target_report = make_mock_elf_report(sections=[target_sec])

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        res = ArtifactComparator.compare_elf_artifacts(
            ref_report, target_report, r1, r2, "sha1", "sha2"
        )

    assert any(d.delta_type == "SECTION_RENAMED" for d in res.structural_deltas)


# --- Scenario 4: Function Byte Modification ---
def test_same_function_modified_code_bytes():
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
        size=20,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="d1",
    )
    sym = ELFSymbolInfo(
        name="do_work",
        symbol_type="STT_FUNC",
        binding="STB_GLOBAL",
        visibility="STV_DEFAULT",
        section_index=0,
        section_name=".text",
        address=0,
        size=10,
        offset=0,
    )

    ref_report = make_mock_elf_report(sections=[sec], symbols=[sym])
    target_report = make_mock_elf_report(sections=[sec], symbols=[sym])

    # Distinct byte contents for function do_work
    ref_bytes = io.BytesIO(b"ORIGINAL_CODE_123456")
    target_bytes = io.BytesIO(b"MODIFIED_CODE_123456")

    with BoundedArtifactReader(ref_bytes) as r1, BoundedArtifactReader(target_bytes) as r2:
        res = ArtifactComparator.compare_elf_artifacts(
            ref_report, target_report, r1, r2, "sha_r", "sha_t"
        )

    mod_funcs = [f for f in res.function_deltas if f.delta_type == "MODIFIED_FUNCTION_CODE"]
    assert len(mod_funcs) == 1
    assert mod_funcs[0].function_name == "do_work"


# --- Scenario 5: Zero-Size Function Handling ---
def test_zero_size_function_handling():
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
        size=20,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="d1",
    )
    sym_zero = ELFSymbolInfo(
        name="empty_stub",
        symbol_type="STT_FUNC",
        binding="STB_GLOBAL",
        visibility="STV_DEFAULT",
        section_index=0,
        section_name=".text",
        address=0,
        size=0,
        offset=0,
    )

    report = make_mock_elf_report(sections=[sec], symbols=[sym_zero])

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        res = ArtifactComparator.compare_elf_artifacts(report, report, r1, r2, "sha1", "sha1")

    # Zero-size function should not produce false MODIFIED_FUNCTION_CODE delta
    assert len([f for f in res.function_deltas if f.delta_type == "MODIFIED_FUNCTION_CODE"]) == 0
    assert any("Zero-size function symbol" in w for w in res.warnings)


# --- Scenario 6: Partial Inventory Suppresses False REMOVED_FUNCTION ---
def test_suppressed_removed_function_partial_inventory():
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
        size=20,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="d1",
    )
    sym = ELFSymbolInfo(
        name="secret_fn",
        symbol_type="STT_FUNC",
        binding="STB_GLOBAL",
        visibility="STV_DEFAULT",
        section_index=0,
        section_name=".text",
        address=0,
        size=10,
        offset=0,
    )

    # Reference is complete, target has sections but stripped symbols (PARTIAL inventory)
    ref_report = make_mock_elf_report(sections=[sec], symbols=[sym], is_stripped=False)
    target_report = make_mock_elf_report(sections=[sec], symbols=[], is_stripped=True)

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        res = ArtifactComparator.compare_elf_artifacts(
            ref_report, target_report, r1, r2, "sha1", "sha2"
        )

    assert res.is_partial_comparison is True
    assert res.target_completeness == FunctionInventoryCompleteness.PARTIAL
    # REMOVED_FUNCTION MUST BE SUPPRESSED under partial inventory
    removed = [f for f in res.function_deltas if f.delta_type == "REMOVED_FUNCTION"]
    assert len(removed) == 0


# --- Scenario 7: Granular W+X Evidence ---
def test_wx_section_and_segment_introduced():
    ref_report = make_mock_elf_report(has_wx_sections=False, has_wx_load_segments=False)
    target_report = make_mock_elf_report(has_wx_sections=True, has_wx_load_segments=True)

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        res = ArtifactComparator.compare_elf_artifacts(
            ref_report, target_report, r1, r2, "sha1", "sha2"
        )

    obs_types = [s.observation_type for s in res.security_observation_deltas]
    assert "WX_SECTION_INTRODUCED" in obs_types
    assert "WX_LOAD_SEGMENT_INTRODUCED" in obs_types


# --- Scenario 8: ELF Header Compatibility Validation (PG-4001) ---
def test_elf_class_mismatch_raises_pg4001():
    ref_report = make_mock_elf_report(e_class=2)  # ELF64
    target_report = make_mock_elf_report(e_class=1)  # ELF32

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        with pytest.raises(ELFCompatibilityError) as exc:
            ArtifactComparator.compare_elf_artifacts(ref_report, target_report, r1, r2, "s1", "s2")
    assert exc.value.error_code == "PG-4001"


def test_e_machine_mismatch_raises_pg4001():
    ref_report = make_mock_elf_report(e_machine=62)  # x86_64
    target_report = make_mock_elf_report(e_machine=183)  # AArch64

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        with pytest.raises(ELFCompatibilityError) as exc:
            ArtifactComparator.compare_elf_artifacts(ref_report, target_report, r1, r2, "s1", "s2")
    assert exc.value.error_code == "PG-4001"


# --- Scenario 9: Incompatible Media Type (PG-4002) ---
def test_media_type_mismatch_raises_pg4002():
    report = make_mock_elf_report()

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        with pytest.raises(IncompatibleArtifactTypeError) as exc:
            ArtifactComparator.compare_elf_artifacts(
                report,
                report,
                r1,
                r2,
                "s1",
                "s2",
                reference_media_type="application/x-elf",
                target_media_type="application/zip",
            )
    assert exc.value.error_code == "PG-4002"


# --- Scenario 10: Deterministic Output Serialization ---
def test_deterministic_serialization_stability():
    sec1 = ELFSectionInfo(
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
        section_digest="d1",
    )
    sec2 = ELFSectionInfo(
        index=1,
        name=".data",
        section_type=1,
        section_type_name="SHT_PROGBITS",
        flags=3,
        is_alloc=True,
        is_write=True,
        is_exec=False,
        address=0,
        offset=0,
        size=10,
        link=0,
        info=0,
        addralign=16,
        entsize=0,
        section_digest="d2",
    )
    report = make_mock_elf_report(sections=[sec1, sec2])

    s1 = io.BytesIO(b"0" * 50)
    s2 = io.BytesIO(b"0" * 50)
    with BoundedArtifactReader(s1) as r1, BoundedArtifactReader(s2) as r2:
        res1 = ArtifactComparator.compare_elf_artifacts(report, report, r1, r2, "s1", "s1")
        res2 = ArtifactComparator.compare_elf_artifacts(report, report, r1, r2, "s1", "s1")

    assert res1.model_dump_json() == res2.model_dump_json()
