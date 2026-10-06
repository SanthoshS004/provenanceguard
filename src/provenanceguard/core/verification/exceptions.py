"""
Verification Subsystem Exceptions
"""

from typing import Optional


class ComparisonError(Exception):
    """Base exception for all verification and comparison errors."""

    def __init__(self, error_code: str, message: str, details: Optional[str] = None):
        super().__init__(f"[{error_code}] {message}")
        self.error_code = error_code
        self.message = message
        self.details = details


class AuthoritativeDigestMismatchError(ComparisonError):
    """Raised when an artifact reader calculated SHA-256 does not match authoritative claim."""

    def __init__(self, expected: str, calculated: str):
        super().__init__(
            "PG-4003",
            f"Authoritative artifact SHA-256 digest mismatch: "
            f"expected {expected}, calculated {calculated}",
        )
        self.expected = expected
        self.calculated = calculated


class ELFCompatibilityError(ComparisonError):
    """Raised when reference and target ELF binaries have incompatible headers (PG-4001)."""

    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__("PG-4001", message, details)


class IncompatibleArtifactTypeError(ComparisonError):
    """Raised when reference and target artifacts have incompatible media types (PG-4002)."""

    def __init__(self, reference_type: str, target_type: str):
        super().__init__(
            "PG-4002",
            f"Incompatible artifact media types for comparison: "
            f"reference '{reference_type}' vs target '{target_type}'",
        )
        self.reference_type = reference_type
        self.target_type = target_type


class VerificationError(ComparisonError):
    """Base exception for attestation and provenance verification errors."""

    pass


class DSSEVerificationError(VerificationError):
    """Raised when DSSE envelope verification fails (PG-5001)."""

    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__("PG-5001", message, details)


class ProvenanceValidationError(VerificationError):
    """Raised when in-toto Statement v1 or SLSA v1.2 validation fails (PG-5002)."""

    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__("PG-5002", message, details)


class SigstoreVerificationError(VerificationError):
    """Raised when Sigstore bundle, Fulcio, or Rekor verification fails (PG-5003)."""

    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__("PG-5003", message, details)


class SubjectDigestMismatchFinding(VerificationError):
    """Domain finding when zero matching subjects are found in a valid statement (PG-5004)."""

    def __init__(self, message: str, details: Optional[str] = None):
        super().__init__("PG-5004", message, details)
