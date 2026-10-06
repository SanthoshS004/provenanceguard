"""
Domain Enumerations for ProvenanceGuard
"""

from enum import Enum


class MediaType(str, Enum):
    ELF = "application/vnd.elf"
    GZIP = "application/gzip"
    TAR = "application/x-tar"
    ZIP = "application/zip"
    JSON = "application/json"
    SPDX_JSON = "application/spdx+json"
    CYCLONEDX_JSON = "application/vnd.cyclonedx+json"
    UNKNOWN = "application/octet-stream"


class DigestAlgorithm(str, Enum):
    SHA256 = "sha256"
    SHA512 = "sha512"


class ScmProvider(str, Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    BITBUCKET = "bitbucket"
    CUSTOM = "custom"


class ExecutionStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(str, Enum):
    FUNCTION_ADDED = "FUNCTION_ADDED"
    FUNCTION_REMOVED = "FUNCTION_REMOVED"
    FUNCTION_CODE_CHANGED = "FUNCTION_CODE_CHANGED"
    UNEXPECTED_DEPENDENCY = "UNEXPECTED_DEPENDENCY"
    MISSING_DEPENDENCY = "MISSING_DEPENDENCY"
    DEPENDENCY_DIGEST_MISMATCH = "DEPENDENCY_DIGEST_MISMATCH"
    PROVENANCE_INVALID = "PROVENANCE_INVALID"
    PROVENANCE_MISSING = "PROVENANCE_MISSING"
    PROVENANCE_TAMPERED = "PROVENANCE_TAMPERED"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SIGNATURE_MISSING = "SIGNATURE_MISSING"
    UNTRUSTED_BUILDER = "UNTRUSTED_BUILDER"
    DIGEST_MISMATCH = "DIGEST_MISMATCH"
    REPRODUCIBILITY_FAILURE = "REPRODUCIBILITY_FAILURE"
    SUSPICIOUS_STRUCTURE = "SUSPICIOUS_STRUCTURE"
    MANDATORY_RULE_VIOLATION = "MANDATORY_RULE_VIOLATION"
    RISK_THRESHOLD_EXCEEDED = "RISK_THRESHOLD_EXCEEDED"


class Decision(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNING = "PASS_WITH_WARNING"
    BLOCK = "BLOCK"


class AttestationType(str, Enum):
    SLSA_V12 = "https://slsa.dev/provenance/v1"
    IN_TOTO_STATEMENT = "https://in-toto.io/Statement/v0.1"
    IN_TOTO_STATEMENT_V1 = "https://in-toto.io/Statement/v1.0"
    CUSTOM = "custom"
