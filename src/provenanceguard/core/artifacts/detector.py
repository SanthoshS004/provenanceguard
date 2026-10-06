"""
Magic-Byte & Structural JSON Media Type Detector for ProvenanceGuard.
Determines authoritative MediaType by inspecting binary header bytes and structural markers.
CRITICAL INVARIANT: Gzip streams are classified as GZIP or TAR, NOT OCI.
Filenames and MIME headers are ignored.
"""

import json
from pathlib import Path
from typing import BinaryIO

from provenanceguard.core.domain.enums import MediaType

MAX_INSPECTION_BYTES = 8192  # Inspect up to first 8 KiB for headers


def detect_media_type_from_bytes(header_bytes: bytes) -> MediaType:
    """
    Classifies media type from an initial chunk of header bytes.
    """
    if not header_bytes:
        return MediaType.UNKNOWN

    # 1. ELF Executable
    if header_bytes.startswith(b"\x7fELF"):
        return MediaType.ELF

    # 2. GZIP Stream (Note: Gzip is GZIP, not OCI!)
    if header_bytes.startswith(b"\x1f\x8b"):
        return MediaType.GZIP

    # 3. ZIP Archive
    if header_bytes.startswith(b"\x50\x4b\x03\x04") or header_bytes.startswith(b"\x50\x4b\x05\x06"):
        return MediaType.ZIP

    # 4. TAR Archive (Standard ustar magic header at offset 257)
    if len(header_bytes) >= 262 and header_bytes[257:262] in (b"ustar", b"ustar\x00"):
        return MediaType.TAR

    # 5. JSON & Structural Document Inspection
    # Remove UTF-8 BOM if present
    clean_bytes = header_bytes
    if clean_bytes.startswith(b"\xef\xbb\xbf"):
        clean_bytes = clean_bytes[3:]

    stripped_text = clean_bytes.lstrip()
    if stripped_text.startswith(b"{") or stripped_text.startswith(b"["):
        try:
            # Decode up to inspection bytes
            text_snippet = stripped_text.decode("utf-8", errors="ignore")
            parsed_json = json.loads(text_snippet[:MAX_INSPECTION_BYTES])
            if isinstance(parsed_json, dict):
                if "spdxVersion" in parsed_json or "SPDXID" in parsed_json:
                    return MediaType.SPDX_JSON
                if parsed_json.get("bomFormat") == "CycloneDX":
                    return MediaType.CYCLONEDX_JSON
            return MediaType.JSON
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Partial or invalid JSON header snippet
            pass

    return MediaType.UNKNOWN


def detect_media_type_from_stream(stream: BinaryIO) -> MediaType:
    """
    Inspects media type from a binary input stream without consuming the entire stream.
    Restores stream position if stream is seekable.
    """
    start_pos = 0
    if stream.seekable():
        start_pos = stream.tell()

    header_bytes = stream.read(MAX_INSPECTION_BYTES)

    if stream.seekable():
        stream.seek(start_pos)

    return detect_media_type_from_bytes(header_bytes)


def detect_media_type_from_file(file_path: Path) -> MediaType:
    """
    Inspects media type from a file on disk.
    """
    if not file_path.exists():
        return MediaType.UNKNOWN

    with open(file_path, "rb") as f:
        return detect_media_type_from_stream(f)
