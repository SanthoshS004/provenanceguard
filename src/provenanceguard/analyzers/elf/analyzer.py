"""
ELFAnalyzer Implementation conforming to ArtifactAnalyzer Protocol.
Extracts static ELF structural evidence without binary execution.
INVARIANT: Produces security evidence observations ONLY.
Does NOT output verdicts such as SAFE, MALICIOUS, PASS, or BLOCK.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from provenanceguard.analyzers.base import (
    AnalyzerCapabilities,
    AnalyzerResult,
    ArtifactAnalyzer,
)
from provenanceguard.analyzers.elf.exceptions import (
    ELFResourceLimitError,
)
from provenanceguard.analyzers.elf.models import (
    ELFAnalysisReport,
    ELFResourceLimits,
)
from provenanceguard.analyzers.elf.parser import StaticELFParser
from provenanceguard.core.domain.enums import MediaType


class ELFAnalyzer(ArtifactAnalyzer):
    """
    Concrete ArtifactAnalyzer for Linux ELF Binaries.
    """

    def __init__(self, limits: Optional[ELFResourceLimits] = None):
        self.limits = limits or ELFResourceLimits()

    def supports(self, media_type: str) -> bool:
        return media_type == MediaType.ELF or media_type == MediaType.ELF.value

    def capabilities(self) -> AnalyzerCapabilities:
        return AnalyzerCapabilities(
            supports_binary_diff=True,
            supports_symbol_table=True,
            supports_sbom_parsing=False,
            supported_architectures=["x86_64", "i386", "aarch64", "ARM", "RISC-V"],
        )

    def analyze_report(self, artifact_path: Path) -> ELFAnalysisReport:
        """
        Parses ELF binary on disk and produces detailed ELFAnalysisReport domain object.
        """
        if not artifact_path.exists():
            raise FileNotFoundError(f"ELF binary file not found: {artifact_path}")

        file_size = artifact_path.stat().st_size
        if file_size > self.limits.max_analysis_file_size:
            raise ELFResourceLimitError(
                f"File size ({file_size} bytes) exceeds limit "
                f"({self.limits.max_analysis_file_size} bytes)"
            )

        warnings: List[str] = []
        is_truncated = False

        with open(artifact_path, "rb") as stream:
            parser = StaticELFParser(stream, limits=self.limits)
            header = parser.parse_header()

            program_headers = parser.parse_program_headers(header)
            sections, _ = parser.parse_sections(header)
            symbols = parser.parse_symbols(header, sections)
            imported_libs = parser.parse_dynamic_imports(header, sections)

        # 1. Identify Symbol-Derived Functions ONLY (STT_FUNC)
        symbol_derived_functions = [s for s in symbols if s.symbol_type == "STT_FUNC"]

        # 2. Stripped Binary Observation (.symtab check)
        has_symtab = any(sec.section_type == 2 for sec in sections)  # SHT_SYMTAB = 2
        is_stripped = not has_symtab
        if is_stripped:
            warnings.append(
                "Binary is stripped: .symtab section absent. "
                "Functions derived from .dynsym only if present."
            )

        # 3. W+X Section Observation
        has_wx_sections = any(sec.is_write and sec.is_exec for sec in sections)

        # 4. W+X Program Load Segment Observation
        has_wx_load_segments = any(seg.is_write and seg.is_exec for seg in program_headers)

        # 5. Collect Section Anomalies & Security Observations
        section_anomalies: List[Dict[str, Any]] = []
        security_observations: List[Dict[str, Any]] = []

        if has_wx_sections:
            security_observations.append(
                {
                    "observation": "WX_SECTION_PRESENT",
                    "details": (
                        "One or more sections are marked as both writable and executable "
                        "(SHF_WRITE + SHF_EXECINSTR)."
                    ),
                }
            )

        if has_wx_load_segments:
            security_observations.append(
                {
                    "observation": "WX_LOAD_SEGMENT_PRESENT",
                    "details": (
                        "One or more PT_LOAD segments are marked as both writable and executable "
                        "(PF_W + PF_X)."
                    ),
                }
            )

        for sec in sections:
            if sec.name in (".text", ".rodata") and sec.is_write:
                section_anomalies.append(
                    {
                        "anomaly": "WRITABLE_CODE_SECTION",
                        "section": sec.name,
                        "details": (
                            f"Section '{sec.name}' is unexpectedly marked writable (SHF_WRITE)."
                        ),
                    }
                )

        return ELFAnalysisReport(
            header=header,
            program_headers=program_headers,
            sections=sections,
            symbol_derived_functions=symbol_derived_functions,
            all_symbols=symbols,
            imported_libraries=imported_libs,
            section_anomalies=section_anomalies,
            security_observations=security_observations,
            is_stripped=is_stripped,
            has_wx_sections=has_wx_sections,
            has_wx_load_segments=has_wx_load_segments,
            is_truncated=is_truncated,
            warnings=warnings,
        )

    def analyze(self, artifact_path: Path) -> AnalyzerResult:
        """
        Implements ArtifactAnalyzer protocol returning generic AnalyzerResult.
        """
        report = self.analyze_report(artifact_path)

        sections_dict = [sec.model_dump() for sec in report.sections]
        functions_dict = [fn.model_dump() for fn in report.symbol_derived_functions]

        return AnalyzerResult(
            artifact_type="elf",
            architecture=report.header.architecture_name,
            bits=64 if report.header.e_class == 2 else 32,
            sections=sections_dict,
            functions=functions_dict,
            imports=report.imported_libraries,
            warnings=report.warnings,
        )
