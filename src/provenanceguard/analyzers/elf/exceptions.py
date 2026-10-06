"""
ELF Analyzer Exceptions & Error Codes
"""

from provenanceguard.core.domain.exceptions import DomainError


class ELFAnalyzerError(DomainError):
    """Base exception for all ELF analyzer operations."""

    def __init__(self, error_code: str, message: str, details: list[str] | None = None):
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message
        self.details = details or []


class ELFParseError(ELFAnalyzerError):
    """Raised when an ELF binary header, section table, or symbol table fails validation."""

    pass


class ELFResourceLimitError(ELFAnalyzerError):
    """Raised when an ELF binary exceeds configured resource caps."""

    def __init__(self, message: str, details: list[str] | None = None):
        super().__init__(
            error_code="PG-3003",
            message=message,
            details=details,
        )
