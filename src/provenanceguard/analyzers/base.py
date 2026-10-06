"""
Base Abstract Interface for Artifact Analyzers
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class AnalyzerCapabilities(BaseModel):
    supports_binary_diff: bool = False
    supports_symbol_table: bool = False
    supports_sbom_parsing: bool = False
    supported_architectures: List[str] = []


class AnalyzerResult(BaseModel):
    artifact_type: str
    architecture: Optional[str] = None
    bits: Optional[int] = None
    sections: List[Dict[str, Any]] = []
    functions: List[Dict[str, Any]] = []
    imports: List[str] = []
    warnings: List[str] = []


class ArtifactAnalyzer(ABC):
    """
    Abstract interface for all artifact analyzers (ELF, OCI, SBOM, etc.).
    """

    @abstractmethod
    def supports(self, media_type: str) -> bool:
        """Returns True if the analyzer handles the given media type."""
        pass

    @abstractmethod
    def analyze(self, artifact_path: Path) -> AnalyzerResult:
        """Analyzes the artifact file statically without execution."""
        pass

    @abstractmethod
    def capabilities(self) -> AnalyzerCapabilities:
        """Returns capabilities of this analyzer implementation."""
        pass
