"""
Custom Exceptions for Isolated Builder Engine
"""


class BuilderError(Exception):
    """Base exception for all isolated builder errors."""

    pass


class IsolationViolationError(BuilderError):
    """Raised when container runtime security invariants are violated."""

    pass


class ImageResolutionError(BuilderError):
    """Raised when image digest resolution or repository manifest verification fails."""

    pass


class SymlinkViolationError(BuilderError):
    """Raised when a symlink is encountered during artifact collection."""

    pass


class SpecialFileViolationError(BuilderError):
    """Raised when a hardlink, FIFO, socket, device, or special file is encountered."""

    pass


class SCMValidationError(BuilderError):
    """Raised when SCM URL validation fails (empty URL or embedded credentials)."""

    pass


class TimeoutError(BuilderError):
    """Raised when build execution exceeds configured timeout boundary."""

    pass


class CleanupError(BuilderError):
    """Raised when container removal or host workspace teardown fails."""

    pass


class ArtifactCollectionError(BuilderError):
    """Raised when artifact bounds or collection integrity rules are breached."""

    pass


class SecurityViolationError(BuilderError):
    """Raised when a security invariant or non-world-writable permission rule is violated."""

    pass
