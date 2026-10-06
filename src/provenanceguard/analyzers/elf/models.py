"""
ELF Analyzer Domain & Report Models
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ELFResourceLimits(BaseModel):
    """
    Configurable analysis resource caps for hostile ELF payloads.
    """

    model_config = ConfigDict(frozen=True)

    max_analysis_file_size: int = Field(default=500 * 1024 * 1024)  # 500 MB max
    max_sections: int = Field(default=1000)
    max_program_headers: int = Field(default=256)
    max_symbols: int = Field(default=50000)
    max_dynamic_entries: int = Field(default=5000)
    max_relocations: int = Field(default=50000)
    max_string_table_size: int = Field(default=10 * 1024 * 1024)  # 10 MB max
    max_functions: int = Field(default=50000)
    max_total_bytes_processed: int = Field(default=500 * 1024 * 1024)
    max_report_size: int = Field(default=10 * 1024 * 1024)


class ELFHeaderInfo(BaseModel):
    """
    ELF File Header Metadata.
    """

    model_config = ConfigDict(frozen=True)

    e_class: int  # 1 = 32-bit (ELFCLASS32), 2 = 64-bit (ELFCLASS64)
    class_name: str  # "ELF32" or "ELF64"
    endianness: str  # "little" or "big"
    e_machine: int  # Raw integer architecture machine ID (e.g. 62 = x86_64, 3 = i386)
    architecture_name: str  # "x86_64", "i386", "aarch64", "unknown (e_machine=N)"
    entry_point: int
    e_phoff: int
    e_shoff: int
    e_flags: int
    e_ehsize: int
    e_phentsize: int
    e_phnum: int
    e_shentsize: int
    e_shnum: int
    e_shstrndx: int


class ELFSectionInfo(BaseModel):
    """
    ELF Section Header Metadata.
    """

    model_config = ConfigDict(frozen=True)

    index: int
    name: str
    section_type: int
    section_type_name: str
    flags: int
    is_alloc: bool
    is_write: bool
    is_exec: bool
    address: int
    offset: int
    size: int
    link: int
    info: int
    addralign: int
    entsize: int
    section_digest: Optional[str] = None  # SHA-256 hex string of raw section content bytes


class ELFSegmentInfo(BaseModel):
    """
    ELF Program Header (Load Segment) Metadata.
    """

    model_config = ConfigDict(frozen=True)

    index: int
    segment_type: int
    segment_type_name: str
    flags: int
    is_read: bool
    is_write: bool
    is_exec: bool
    offset: int
    vaddr: int
    paddr: int
    filesz: int
    memsz: int
    align: int


class ELFSymbolInfo(BaseModel):
    """
    ELF Symbol Entry Metadata.
    Note: Symbols represent symbol-table entries (STT_FUNC/STT_OBJECT).
    """

    model_config = ConfigDict(frozen=True)

    name: str
    symbol_type: str  # "STT_FUNC", "STT_OBJECT", "STT_NOTYPE", etc.
    binding: str  # "STB_LOCAL", "STB_GLOBAL", "STB_WEAK", etc.
    visibility: str
    section_index: int
    section_name: Optional[str] = None
    address: int
    size: int


class ELFAnalysisReport(BaseModel):
    """
    Structured ELF Analysis Output Evidence.
    CRITICAL INVARIANT: Contains raw evidence observations ONLY.
    Does NOT output verdicts such as SAFE, MALICIOUS, PASS, or BLOCK.
    """

    header: ELFHeaderInfo
    program_headers: List[ELFSegmentInfo] = Field(default_factory=list)
    sections: List[ELFSectionInfo] = Field(default_factory=list)
    symbol_derived_functions: List[ELFSymbolInfo] = Field(default_factory=list)
    all_symbols: List[ELFSymbolInfo] = Field(default_factory=list)
    imported_libraries: List[str] = Field(default_factory=list)
    section_anomalies: List[Dict[str, Any]] = Field(default_factory=list)
    security_observations: List[Dict[str, Any]] = Field(default_factory=list)
    is_stripped: bool = False
    has_wx_sections: bool = False
    has_wx_load_segments: bool = False
    is_truncated: bool = False
    warnings: List[str] = Field(default_factory=list)
