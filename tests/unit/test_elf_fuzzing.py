"""
Fuzzing & Property-Based Test Suite for ELF Analyzer (Phase 3)
Verifies parser robustness: Random bit flips, truncated byte streams, and corrupted table headers
MUST NEVER cause unhandled system crashes, infinite loops, or host binary execution.
"""

import io
import random
import struct

from provenanceguard.analyzers.elf.analyzer import ELFAnalyzer
from provenanceguard.analyzers.elf.exceptions import ELFAnalyzerError
from provenanceguard.analyzers.elf.parser import StaticELFParser


def make_valid_elf64() -> bytes:
    """Helper creating a minimal valid 64-bit ELF binary."""
    ident = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    header = struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, 0x400000, 64, 120, 0, 64, 56, 1, 64, 2, 1)
    phdr = struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 256, 256, 4096)
    shdr0 = b"\x00" * 64
    shdr1 = struct.pack("<IIQQQQIIQQ", 1, 3, 0, 0, 248, 11, 0, 0, 1, 0)
    shstrtab = b"\x00.shstrtab\x00"
    return ident + header + phdr + shdr0 + shdr1 + shstrtab


def test_fuzz_truncated_byte_streams():
    """
    Fuzz test: Feeds progressively truncated ELF byte streams into parser.
    Ensures parser cleanly handles truncation via ELFParseError or safe return.
    """
    base_bytes = make_valid_elf64()

    for i in range(1, len(base_bytes)):
        truncated = base_bytes[:i]
        stream = io.BytesIO(truncated)
        try:
            parser = StaticELFParser(stream)
            h = parser.parse_header()
            _ = parser.parse_program_headers(h)
            s, _ = parser.parse_sections(h)
            parser.parse_symbols(h, s)
        except (ELFAnalyzerError, FileNotFoundError):
            # Safe handled exception
            pass


def test_fuzz_random_byte_mutations(tmp_path):
    """
    Fuzz test: Mutates random bytes in a valid ELF header.
    Asserts parser raises controlled ELFAnalyzerError or returns structured report cleanly.
    """
    base_bytes = bytearray(make_valid_elf64())
    random.seed(42)  # Deterministic seed

    for run in range(50):
        mutated = bytearray(base_bytes)
        # Flip 1 to 5 random bytes
        num_flips = random.randint(1, 5)
        for _ in range(num_flips):
            idx = random.randint(0, len(mutated) - 1)
            mutated[idx] = random.randint(0, 255)

        p = tmp_path / f"fuzz_{run}.elf"
        p.write_bytes(mutated)

        analyzer = ELFAnalyzer()
        try:
            analyzer.analyze_report(p)
        except ELFAnalyzerError:
            # Safe handled exception
            pass
