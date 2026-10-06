"""
Function Byte-Level Fingerprinting Module
"""

import hashlib
from typing import List, Optional

from provenanceguard.analyzers.elf.models import ELFSectionInfo
from provenanceguard.core.verification.artifact_reader import BoundedArtifactReader
from provenanceguard.core.verification.models import FunctionCodeDigest, FunctionMetadata


class FunctionFingerprinter:
    """
    Calculates deterministic SHA-256 byte-level code digests for functions
    using safe, bounded read-only artifact readers.
    """

    @staticmethod
    def compute_function_code_digest(
        func: FunctionMetadata,
        reader: BoundedArtifactReader,
        sections: Optional[List[ELFSectionInfo]] = None,
    ) -> FunctionCodeDigest:
        """
        Computes SHA-256 hex digest of the raw byte slice [offset : offset + size].
        Enforces range safety, zero-size handling, and executable section validation.
        """
        # 1. Zero-size function handling
        if func.size == 0:
            return FunctionCodeDigest(
                function_name=func.name,
                raw_bytes_sha256=None,
                size_bytes=0,
                is_zero_size=True,
                is_valid_range=True,
                warning="Zero-size function symbol: code digest skipped.",
            )

        # 2. Bounds and size cap validation
        if func.offset < 0 or func.size < 0:
            return FunctionCodeDigest(
                function_name=func.name,
                raw_bytes_sha256=None,
                size_bytes=func.size,
                is_valid_range=False,
                warning=f"Invalid negative offset ({func.offset}) or size ({func.size}).",
            )

        if func.offset + func.size > reader.file_size:
            return FunctionCodeDigest(
                function_name=func.name,
                raw_bytes_sha256=None,
                size_bytes=func.size,
                is_valid_range=False,
                warning=(
                    f"Function range [{func.offset}:{func.offset + func.size}] "
                    f"exceeds file bounds ({reader.file_size})."
                ),
            )

        if func.size > reader.max_read_cap_bytes:
            return FunctionCodeDigest(
                function_name=func.name,
                raw_bytes_sha256=None,
                size_bytes=func.size,
                is_valid_range=False,
                warning=(
                    f"Function size ({func.size} bytes) exceeds read cap "
                    f"({reader.max_read_cap_bytes} bytes)."
                ),
            )

        # 3. Executable section verification (if sections metadata available)
        if sections:
            in_exec_section = any(
                sec.is_exec and (sec.offset <= func.offset < sec.offset + max(sec.size, 1))
                for sec in sections
            )
            if not in_exec_section:
                return FunctionCodeDigest(
                    function_name=func.name,
                    raw_bytes_sha256=None,
                    size_bytes=func.size,
                    is_valid_range=False,
                    warning=(
                        f"Function offset {func.offset} does not reside "
                        f"within an executable section."
                    ),
                )

        # 4. Safe raw byte reading and SHA-256 calculation
        try:
            raw_bytes = reader.read_bytes_at(func.offset, func.size)
            digest = hashlib.sha256(raw_bytes).hexdigest()
            return FunctionCodeDigest(
                function_name=func.name,
                raw_bytes_sha256=digest,
                size_bytes=func.size,
                is_zero_size=False,
                is_valid_range=True,
            )
        except Exception as exc:
            return FunctionCodeDigest(
                function_name=func.name,
                raw_bytes_sha256=None,
                size_bytes=func.size,
                is_valid_range=False,
                warning=f"Failed to read function bytes: {str(exc)}",
            )
