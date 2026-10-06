"""
Pure Python Static ELF Binary Parser with Overflow-Safe Bounds Checking.
Operates on file-backed seekable streams without binary execution or CLI readelf dependencies.
"""

import hashlib
import struct
from typing import BinaryIO, List, Optional, Tuple

from provenanceguard.analyzers.elf.exceptions import ELFParseError
from provenanceguard.analyzers.elf.models import (
    ELFHeaderInfo,
    ELFResourceLimits,
    ELFSectionInfo,
    ELFSegmentInfo,
    ELFSymbolInfo,
)

# Standard machine architecture mapping
MACHINE_MAP = {
    3: "i386",
    4: "ARM",
    62: "x86_64",
    183: "aarch64",
    243: "RISC-V",
}

# ELF Section Constants
SHF_WRITE = 0x1
SHF_ALLOC = 0x2
SHF_EXECINSTR = 0x4

SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_DYNAMIC = 6
SHT_NOBITS = 8
SHT_REL = 9
SHT_DYNSYM = 11

# Program Header Constants
PT_LOAD = 1
PT_DYNAMIC = 2
PF_X = 1
PF_W = 2
PF_R = 4

# Symbol Constants
STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4

STT_NAMES = {
    0: "STT_NOTYPE",
    1: "STT_OBJECT",
    2: "STT_FUNC",
    3: "STT_SECTION",
    4: "STT_FILE",
}

STB_NAMES = {
    0: "STB_LOCAL",
    1: "STB_GLOBAL",
    2: "STB_WEAK",
}

DT_NEEDED = 1
DT_STRTAB = 5


def check_bounds(offset: int, size: int, file_size: int, desc: str = "Region"):
    """
    Validates that offset and size do not overflow or escape file bounds.
    """
    if offset < 0 or size < 0:
        raise ELFParseError(
            "PG-3002", f"Negative offset or size in {desc}: offset={offset}, size={size}"
        )
    if offset > file_size or size > file_size - offset:
        raise ELFParseError(
            "PG-3002",
            f"Bounds violation in {desc}: offset {offset} + size {size} "
            f"exceeds file size {file_size}",
        )


def check_overflow_mult(count: int, entry_size: int, file_size: int, desc: str = "Table"):
    """
    Validates integer multiplication overflow and verifies total table size against file size.
    """
    if count < 0 or entry_size < 0:
        raise ELFParseError("PG-3002", f"Negative count or entry size in {desc}")
    if count == 0 or entry_size == 0:
        return
    total = count * entry_size
    if total // count != entry_size:
        raise ELFParseError("PG-3002", f"Integer overflow detected during multiplication in {desc}")
    if total > file_size:
        raise ELFParseError(
            "PG-3002", f"Table size {total} in {desc} exceeds total file size {file_size}"
        )


def parse_null_string(data: bytes, offset: int, max_len: int = 4096) -> str:
    """
    Reads a null-terminated UTF-8 string safely from bytes with length cap.
    """
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset)
    if end == -1:
        end = min(offset + max_len, len(data))
    raw = data[offset:end]
    return raw.decode("utf-8", errors="replace")


class StaticELFParser:
    """
    Pure Python static ELF binary parser.
    """

    def __init__(self, stream: BinaryIO, limits: Optional[ELFResourceLimits] = None):
        self.stream = stream
        self.limits = limits or ELFResourceLimits()

        # Seek file size
        self.stream.seek(0, 2)
        self.file_size = self.stream.tell()
        self.stream.seek(0)

        if self.file_size < 16:
            raise ELFParseError(
                "PG-3001",
                f"File size ({self.file_size} bytes) is too small to be a valid ELF binary",
            )

    def parse_header(self) -> ELFHeaderInfo:
        """
        Parses ELF Header.
        """
        self.stream.seek(0)
        e_ident = self.stream.read(16)
        if len(e_ident) < 16:
            raise ELFParseError("PG-3001", "Truncated ELF identification header")

        if not e_ident.startswith(b"\x7fELF"):
            raise ELFParseError("PG-3001", "Invalid magic bytes: file is not an ELF binary")

        e_class = e_ident[4]
        if e_class not in (1, 2):
            raise ELFParseError("PG-3004", f"Invalid ELF class identifier: {e_class}")

        e_data = e_ident[5]
        if e_data == 1:
            endian = "<"  # Little-endian
            endian_name = "little"
        elif e_data == 2:
            endian = ">"  # Big-endian
            endian_name = "big"
        else:
            raise ELFParseError("PG-3004", f"Invalid ELF endianness identifier: {e_data}")

        is_64 = e_class == 2
        header_fmt = f"{endian}HHIIIIIHHHHHH" if not is_64 else f"{endian}HHIQQQIHHHHHH"
        header_size = struct.calcsize(header_fmt)

        self.stream.seek(16)
        header_bytes = self.stream.read(header_size)
        if len(header_bytes) < header_size:
            raise ELFParseError("PG-3001", "Truncated ELF header fields")

        fields = struct.unpack(header_fmt, header_bytes)

        _e_type = fields[0]
        e_machine = fields[1]
        _e_version = fields[2]
        entry_point = fields[3]
        e_phoff = fields[4]
        e_shoff = fields[5]
        e_flags = fields[6]
        e_ehsize = fields[7]
        e_phentsize = fields[8]
        e_phnum = fields[9]
        e_shentsize = fields[10]
        e_shnum = fields[11]
        e_shstrndx = fields[12]

        # Header size validation
        expected_ehsize = 52 if not is_64 else 64
        if e_ehsize < expected_ehsize:
            raise ELFParseError(
                "PG-3002",
                f"Invalid e_ehsize {e_ehsize} (expected >={expected_ehsize})",
            )

        arch_name = MACHINE_MAP.get(e_machine, f"unknown (e_machine={e_machine})")

        return ELFHeaderInfo(
            e_class=e_class,
            class_name="ELF64" if is_64 else "ELF32",
            endianness=endian_name,
            e_machine=e_machine,
            architecture_name=arch_name,
            entry_point=entry_point,
            e_phoff=e_phoff,
            e_shoff=e_shoff,
            e_flags=e_flags,
            e_ehsize=e_ehsize,
            e_phentsize=e_phentsize,
            e_phnum=e_phnum,
            e_shentsize=e_shentsize,
            e_shnum=e_shnum,
            e_shstrndx=e_shstrndx,
        )

    def parse_program_headers(self, header: ELFHeaderInfo) -> List[ELFSegmentInfo]:
        """
        Parses ELF Program Header Table (Load Segments).
        """
        if header.e_phnum == 0 or header.e_phoff == 0:
            return []

        if header.e_phnum > self.limits.max_program_headers:
            header_count = self.limits.max_program_headers
        else:
            header_count = header.e_phnum

        check_overflow_mult(
            header_count, header.e_phentsize, self.file_size, "Program Header Table"
        )
        check_bounds(
            header.e_phoff,
            header_count * header.e_phentsize,
            self.file_size,
            "Program Header Table Region",
        )

        is_64 = header.e_class == 2
        endian = "<" if header.endianness == "little" else ">"
        fmt = f"{endian}IIQQQQQQ" if is_64 else f"{endian}IIIIIIII"

        segments: List[ELFSegmentInfo] = []

        for i in range(header_count):
            self.stream.seek(header.e_phoff + (i * header.e_phentsize))
            p_bytes = self.stream.read(struct.calcsize(fmt))
            if len(p_bytes) < struct.calcsize(fmt):
                break

            fields = struct.unpack(fmt, p_bytes)
            if is_64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = fields
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = fields

            pt_name_map = {
                1: "PT_LOAD",
                2: "PT_DYNAMIC",
                3: "PT_INTERP",
                4: "PT_NOTE",
                6: "PT_PHDR",
                7: "PT_TLS",
            }
            pt_name = pt_name_map.get(p_type, f"PT_UNKNOWN({p_type})")

            is_exec = bool(p_flags & PF_X)
            is_write = bool(p_flags & PF_W)
            is_read = bool(p_flags & PF_R)

            segments.append(
                ELFSegmentInfo(
                    index=i,
                    segment_type=p_type,
                    segment_type_name=pt_name,
                    flags=p_flags,
                    is_read=is_read,
                    is_write=is_write,
                    is_exec=is_exec,
                    offset=p_offset,
                    vaddr=p_vaddr,
                    paddr=p_paddr,
                    filesz=p_filesz,
                    memsz=p_memsz,
                    align=p_align,
                )
            )

        return segments

    def parse_sections(self, header: ELFHeaderInfo) -> Tuple[List[ELFSectionInfo], bytes]:
        """
        Parses ELF Section Header Table & Section Names String Table.
        Returns Tuple of (list of ELFSectionInfo, section header string table bytes).
        """
        if header.e_shnum == 0 or header.e_shoff == 0:
            return [], b""

        if header.e_shnum > self.limits.max_sections:
            section_count = self.limits.max_sections
        else:
            section_count = header.e_shnum

        check_overflow_mult(
            section_count, header.e_shentsize, self.file_size, "Section Header Table"
        )
        check_bounds(
            header.e_shoff,
            section_count * header.e_shentsize,
            self.file_size,
            "Section Header Table Region",
        )

        is_64 = header.e_class == 2
        endian = "<" if header.endianness == "little" else ">"
        fmt = f"{endian}IIQQQQIIQQ" if is_64 else f"{endian}IIIIIIIIII"
        fmt_size = struct.calcsize(fmt)

        raw_sections = []
        for i in range(section_count):
            self.stream.seek(header.e_shoff + (i * header.e_shentsize))
            s_bytes = self.stream.read(fmt_size)
            if len(s_bytes) < fmt_size:
                break
            fields = struct.unpack(fmt, s_bytes)
            raw_sections.append(fields)

        # Extract section header string table (.shstrtab)
        shstrtab_bytes = b""
        if 0 <= header.e_shstrndx < len(raw_sections):
            shstr_header = raw_sections[header.e_shstrndx]
            shstr_offset = shstr_header[4] if is_64 else shstr_header[4]
            shstr_size = shstr_header[5] if is_64 else shstr_header[5]
            if shstr_size <= self.limits.max_string_table_size:
                try:
                    check_bounds(shstr_offset, shstr_size, self.file_size, ".shstrtab")
                    self.stream.seek(shstr_offset)
                    shstrtab_bytes = self.stream.read(shstr_size)
                except ELFParseError:
                    shstrtab_bytes = b""

        sections: List[ELFSectionInfo] = []
        sht_map = {
            0: "SHT_NULL",
            1: "SHT_PROGBITS",
            2: "SHT_SYMTAB",
            3: "SHT_STRTAB",
            4: "SHT_RELA",
            6: "SHT_DYNAMIC",
            8: "SHT_NOBITS",
            9: "SHT_REL",
            11: "SHT_DYNSYM",
        }

        for i, fields in enumerate(raw_sections):
            (
                sh_name_idx,
                sh_type,
                sh_flags,
                sh_addr,
                sh_offset,
                sh_size,
                sh_link,
                sh_info,
                sh_addralign,
                sh_entsize,
            ) = fields

            sec_name = (
                parse_null_string(shstrtab_bytes, sh_name_idx) if shstrtab_bytes else f"sec_{i}"
            )
            sec_type_name = sht_map.get(sh_type, f"SHT_UNKNOWN({sh_type})")

            is_alloc = bool(sh_flags & SHF_ALLOC)
            is_write = bool(sh_flags & SHF_WRITE)
            is_exec = bool(sh_flags & SHF_EXECINSTR)

            # Calculate SHA-256 section content digest for non-SHT_NOBITS sections
            sec_digest = None
            if sh_type != SHT_NOBITS and sh_size > 0:
                try:
                    check_bounds(sh_offset, sh_size, self.file_size, f"Section {sec_name}")
                    self.stream.seek(sh_offset)
                    sec_bytes = self.stream.read(sh_size)
                    sec_digest = hashlib.sha256(sec_bytes).hexdigest()
                except ELFParseError:
                    sec_digest = None

            sections.append(
                ELFSectionInfo(
                    index=i,
                    name=sec_name,
                    section_type=sh_type,
                    section_type_name=sec_type_name,
                    flags=sh_flags,
                    is_alloc=is_alloc,
                    is_write=is_write,
                    is_exec=is_exec,
                    address=sh_addr,
                    offset=sh_offset,
                    size=sh_size,
                    link=sh_link,
                    info=sh_info,
                    addralign=sh_addralign,
                    entsize=sh_entsize,
                    section_digest=sec_digest,
                )
            )

        return sections, shstrtab_bytes

    def parse_symbols(
        self, header: ELFHeaderInfo, sections: List[ELFSectionInfo]
    ) -> List[ELFSymbolInfo]:
        """
        Parses symbol tables (.symtab and .dynsym).
        """
        symbols: List[ELFSymbolInfo] = []
        is_64 = header.e_class == 2
        endian = "<" if header.endianness == "little" else ">"
        sym_fmt = f"{endian}IBBHQQ" if is_64 else f"{endian}IIIBBH"
        sym_size = struct.calcsize(sym_fmt)

        section_name_map = {sec.index: sec.name for sec in sections}

        for sec in sections:
            if sec.section_type not in (SHT_SYMTAB, SHT_DYNSYM):
                continue

            if sec.size == 0 or sec.entsize == 0:
                continue

            # Fetch associated string table (.strtab or .dynstr)
            strtab_bytes = b""
            if 0 <= sec.link < len(sections):
                str_sec = sections[sec.link]
                if str_sec.size <= self.limits.max_string_table_size:
                    try:
                        check_bounds(
                            str_sec.offset,
                            str_sec.size,
                            self.file_size,
                            f"String table for sec {sec.name}",
                        )
                        self.stream.seek(str_sec.offset)
                        strtab_bytes = self.stream.read(str_sec.size)
                    except ELFParseError:
                        strtab_bytes = b""

            num_symbols = sec.size // sec.entsize
            if num_symbols > self.limits.max_symbols:
                num_symbols = self.limits.max_symbols

            check_overflow_mult(
                num_symbols, sec.entsize, self.file_size, f"Symbol table {sec.name}"
            )
            check_bounds(
                sec.offset,
                num_symbols * sec.entsize,
                self.file_size,
                f"Symbol table region {sec.name}",
            )

            for i in range(num_symbols):
                self.stream.seek(sec.offset + (i * sec.entsize))
                s_bytes = self.stream.read(sym_size)
                if len(s_bytes) < sym_size:
                    break

                fields = struct.unpack(sym_fmt, s_bytes)
                if is_64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = fields
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = fields

                sym_type_num = st_info & 0xF
                sym_bind_num = st_info >> 4

                sym_type = STT_NAMES.get(sym_type_num, f"STT_UNKNOWN({sym_type_num})")
                sym_bind = STB_NAMES.get(sym_bind_num, f"STB_UNKNOWN({sym_bind_num})")

                sym_name = parse_null_string(strtab_bytes, st_name) if strtab_bytes else f"sym_{i}"

                symbols.append(
                    ELFSymbolInfo(
                        name=sym_name,
                        symbol_type=sym_type,
                        binding=sym_bind,
                        visibility="DEFAULT",
                        section_index=st_shndx,
                        section_name=section_name_map.get(st_shndx),
                        address=st_value,
                        size=st_size,
                    )
                )

        return symbols

    def parse_dynamic_imports(
        self, header: ELFHeaderInfo, sections: List[ELFSectionInfo]
    ) -> List[str]:
        """
        Parses dynamic library imports (DT_NEEDED entries from SHT_DYNAMIC section).
        """
        imported_libs: List[str] = []
        dyn_sec = next((s for s in sections if s.section_type == SHT_DYNAMIC), None)
        if not dyn_sec or dyn_sec.size == 0:
            return imported_libs

        # Fetch dynamic string table (.dynstr)
        dynstr_bytes = b""
        if 0 <= dyn_sec.link < len(sections):
            str_sec = sections[dyn_sec.link]
            try:
                check_bounds(str_sec.offset, str_sec.size, self.file_size, ".dynstr")
                self.stream.seek(str_sec.offset)
                dynstr_bytes = self.stream.read(str_sec.size)
            except ELFParseError:
                dynstr_bytes = b""

        is_64 = header.e_class == 2
        endian = "<" if header.endianness == "little" else ">"
        dyn_fmt = f"{endian}qQ" if is_64 else f"{endian}ii"
        dyn_size = struct.calcsize(dyn_fmt)

        entry_count = dyn_sec.size // dyn_size
        if entry_count > self.limits.max_dynamic_entries:
            entry_count = self.limits.max_dynamic_entries

        check_bounds(dyn_sec.offset, entry_count * dyn_size, self.file_size, ".dynamic section")

        for i in range(entry_count):
            self.stream.seek(dyn_sec.offset + (i * dyn_size))
            d_bytes = self.stream.read(dyn_size)
            if len(d_bytes) < dyn_size:
                break

            d_tag, d_val = struct.unpack(dyn_fmt, d_bytes)
            if d_tag == 0:  # DT_NULL
                break

            if d_tag == DT_NEEDED and dynstr_bytes:
                lib_name = parse_null_string(dynstr_bytes, d_val)
                if lib_name and lib_name not in imported_libs:
                    imported_libs.append(lib_name)

        return imported_libs
