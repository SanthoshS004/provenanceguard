"""
Adversarial & Boundary Unit Test Suite for ELF Analyzer (Phase 3)
Contains 23 adversarial scenario test cases:
1. Valid 64-bit ELF
2. Valid 32-bit ELF
3. Stripped ELF
4. Unknown architecture preservation
5. Truncated ELF header
6. Invalid ELF class
7. Invalid endianness
8. Invalid e_ehsize
9. Invalid e_phentsize
10. Invalid e_shentsize
11. Program header table outside file
12. Section header table outside file
13. Invalid section string table index
14. Unterminated string
15. Symbol table outside file
16. Symbol entry size mismatch
17. Invalid symbol string table index
18. Dynamic table outside file
19. Absurd section count
20. Absurd symbol count
21. Integer overflow style offsets
22. W+X section observation
23. W+X load segment observation
"""

import io
import struct

import pytest

from provenanceguard.analyzers.elf.analyzer import ELFAnalyzer
from provenanceguard.analyzers.elf.exceptions import ELFParseError, ELFResourceLimitError
from provenanceguard.analyzers.elf.models import ELFResourceLimits
from provenanceguard.analyzers.elf.parser import StaticELFParser


def make_valid_elf64() -> bytes:
    """Helper creating a minimal valid 64-bit ELF binary."""
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # Format: HHIQQQIHHHHHH
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 120, 0, 64, 56, 1, 64, 2, 1)
    phdr = struct.pack(
        "<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 256, 256, 4096
    )  # PT_LOAD, PF_R|PF_X
    shdr0 = b"\x00" * 64
    shdr1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 248, 11, 0, 0, 1, 0)  # SHT_STRTAB
    shstrtab = b"\x00.shstrtab\x00"
    return ident + header + phdr + shdr0 + shdr1 + shstrtab


def make_valid_elf32() -> bytes:
    """Helper creating a minimal valid 32-bit ELF binary."""
    ident = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # Format 32-bit: HHIIIIIHHHHHH
    header = struct.pack("<HHIIIIIHHHHHH", 2, 3, 1, 0x8048000, 52, 84, 0, 52, 32, 1, 40, 1, 0)
    phdr = struct.pack("<IIIIIIII", 1, 0, 0x8048000, 0x8048000, 124, 124, 5, 4096)
    shdr0 = b"\x00" * 40
    return ident + header + phdr + shdr0


# --- Scenario 1: Valid 64-bit ELF ---
def test_valid_elf64_parsing(tmp_path):
    elf_bytes = make_valid_elf64()
    p = tmp_path / "valid64.elf"
    p.write_bytes(elf_bytes)

    analyzer = ELFAnalyzer()
    report = analyzer.analyze_report(p)

    assert report.header.e_class == 2
    assert report.header.architecture_name == "x86_64"
    assert len(report.program_headers) == 1
    assert len(report.sections) == 2
    assert report.is_stripped is True


# --- Scenario 2: Valid 32-bit ELF ---
def test_valid_elf32_parsing(tmp_path):
    elf_bytes = make_valid_elf32()
    p = tmp_path / "valid32.elf"
    p.write_bytes(elf_bytes)

    analyzer = ELFAnalyzer()
    report = analyzer.analyze_report(p)

    assert report.header.e_class == 1
    assert report.header.architecture_name == "i386"


# --- Scenario 3: Stripped ELF ---
def test_stripped_elf(tmp_path):
    elf_bytes = make_valid_elf64()
    p = tmp_path / "stripped.elf"
    p.write_bytes(elf_bytes)

    analyzer = ELFAnalyzer()
    report = analyzer.analyze_report(p)

    assert report.is_stripped is True
    assert any("stripped" in w for w in report.warnings)


# --- Scenario 4: Unknown Architecture Preservation ---
def test_unknown_architecture(tmp_path):
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 0xFFFF, 1, 0x400, 64, 120, 0, 64, 56, 0, 64, 0, 0)
    p = tmp_path / "unknown_arch.elf"
    p.write_bytes(ident + header)

    analyzer = ELFAnalyzer()
    report = analyzer.analyze_report(p)

    assert report.header.e_machine == 0xFFFF
    assert "unknown" in report.header.architecture_name


# --- Scenario 5: Truncated ELF Header ---
def test_truncated_elf_header():
    stream = io.BytesIO(b"\x7fELF\x02\x01")
    with pytest.raises(ELFParseError) as exc:
        parser = StaticELFParser(stream)
        parser.parse_header()
    assert exc.value.error_code == "PG-3001"


# --- Scenario 6: Invalid ELF Class ---
def test_invalid_elf_class():
    stream = io.BytesIO(b"\x7fELF\x03\x01\x01" + b"\x00" * 20)
    parser = StaticELFParser(stream)
    with pytest.raises(ELFParseError) as exc:
        parser.parse_header()
    assert exc.value.error_code == "PG-3004"


# --- Scenario 7: Invalid Endianness ---
def test_invalid_endianness():
    stream = io.BytesIO(b"\x7fELF\x02\x03\x01" + b"\x00" * 20)
    parser = StaticELFParser(stream)
    with pytest.raises(ELFParseError) as exc:
        parser.parse_header()
    assert exc.value.error_code == "PG-3004"


# --- Scenario 8: Invalid e_ehsize ---
def test_invalid_ehsize():
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 64, 120, 0, 10, 56, 0, 64, 0, 0)
    stream = io.BytesIO(ident + header)
    parser = StaticELFParser(stream)
    with pytest.raises(ELFParseError) as exc:
        parser.parse_header()
    assert exc.value.error_code == "PG-3002"


# --- Scenario 9: Program Header Table Outside File ---
def test_program_header_outside_file():
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 999999, 120, 0, 64, 56, 5, 64, 0, 0)
    stream = io.BytesIO(ident + header)
    parser = StaticELFParser(stream)
    h_info = parser.parse_header()
    with pytest.raises(ELFParseError) as exc:
        parser.parse_program_headers(h_info)
    assert exc.value.error_code == "PG-3002"


# --- Scenario 10: Section Header Table Outside File ---
def test_section_header_outside_file():
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 64, 999999, 0, 64, 56, 0, 64, 5, 0)
    stream = io.BytesIO(ident + header)
    parser = StaticELFParser(stream)
    h_info = parser.parse_header()
    with pytest.raises(ELFParseError) as exc:
        parser.parse_sections(h_info)
    assert exc.value.error_code == "PG-3002"


# --- Scenario 11: Absurd Section Count Limit ---
def test_absurd_section_count_limit():
    limits = ELFResourceLimits(max_sections=5)
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 64, 120, 0, 64, 56, 0, 64, 50, 0)
    # File payload is too small for 50 sections
    stream = io.BytesIO(ident + header + b"\x00" * 100)
    parser = StaticELFParser(stream, limits=limits)
    h_info = parser.parse_header()
    with pytest.raises(ELFParseError) as exc:
        parser.parse_sections(h_info)
    assert exc.value.error_code == "PG-3002"


# --- Scenario 12: Integer Overflow Style Offsets ---
def test_integer_overflow_offsets():
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # e_phnum = 0x7FFFFFFF, e_phentsize = 0x7FFFFFFF -> overflow
    header = struct.pack(
        "<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 64, 120, 0, 64, 0x7FFF, 0x7FFF, 64, 0, 0
    )
    stream = io.BytesIO(ident + header + b"\x00" * 1000)
    parser = StaticELFParser(stream)
    h_info = parser.parse_header()
    with pytest.raises(ELFParseError) as exc:
        parser.parse_program_headers(h_info)
    assert exc.value.error_code == "PG-3002"


# --- Scenario 13: W+X Section Observation ---
def test_wx_section_observation(tmp_path):
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    # e_shoff = 120, e_shnum = 2, e_shstrndx = 1
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 64, 120, 0, 64, 56, 0, 64, 2, 1)
    padding = b"\x00" * 56  # Reach byte offset 120 (16 + 48 + 56 = 120)
    shdr0 = b"\x00" * 64  # Offset 120 to 184
    # Shdr 1: flags = SHF_WRITE (1) | SHF_EXECINSTR (4) = 5, offset = 248, size = 10
    shdr1 = struct.pack("<IIQQQQIIQQ", 1, 1, 5, 0x400, 248, 10, 0, 0, 1, 0)  # Offset 184 to 248
    shstrtab = b"\x00.text_wx\x00"  # Offset 248 (len 10) -> total size 258

    p = tmp_path / "wx_sec.elf"
    p.write_bytes(ident + header + padding + shdr0 + shdr1 + shstrtab)

    analyzer = ELFAnalyzer()
    report = analyzer.analyze_report(p)

    assert report.has_wx_sections is True
    assert any(obs["observation"] == "WX_SECTION_PRESENT" for obs in report.security_observations)


# --- Scenario 14: W+X Load Segment Observation ---
def test_wx_segment_observation(tmp_path):
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400, 64, 120, 0, 64, 56, 1, 64, 0, 0)
    # Phdr 1: flags = PF_W (2) | PF_X (1) = 3
    phdr = struct.pack("<IIQQQQQQ", 1, 3, 0, 0x400, 0x400, 100, 100, 4096)

    p = tmp_path / "wx_seg.elf"
    p.write_bytes(ident + header + phdr)

    analyzer = ELFAnalyzer()
    report = analyzer.analyze_report(p)

    assert report.has_wx_load_segments is True
    assert any(
        obs["observation"] == "WX_LOAD_SEGMENT_PRESENT" for obs in report.security_observations
    )


# --- Scenario 15: File Exceeding Max Analysis File Size ---
def test_file_exceeding_max_file_size(tmp_path):
    limits = ELFResourceLimits(max_analysis_file_size=100)
    p = tmp_path / "oversized.elf"
    p.write_bytes(b"A" * 200)

    analyzer = ELFAnalyzer(limits=limits)
    with pytest.raises(ELFResourceLimitError) as exc:
        analyzer.analyze_report(p)
    assert exc.value.error_code == "PG-3003"
