"""
Domain Validation & Ingestion Exceptions for ProvenanceGuard
"""


class DomainError(Exception):
    """Base class for all domain layer errors."""

    pass


class DomainValidationError(DomainError):
    """Raised when a domain model field or invariant fails validation."""

    def __init__(self, message: str, field_name: str | None = None):
        super().__init__(message)
        self.message = message
        self.field_name = field_name


class IngestionRejectedError(DomainError):
    """
    Raised when raw metadata payload fails schema or structural validation during ingestion.
    NOTE: Ingestion rejection is NOT a policy BLOCK decision. It indicates invalid/malformed input.
    """

    def __init__(self, error_code: str, message: str, details: list[str] | None = None):
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message
        self.details = details or []
