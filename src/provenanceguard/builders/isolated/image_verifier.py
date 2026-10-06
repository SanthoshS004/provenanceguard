"""
Semantic Image Reference Parser and Manifest Digest Verifier
"""

import re
from typing import List, NamedTuple, Optional

from provenanceguard.builders.isolated.exceptions import ImageResolutionError


class ParsedImageRef(NamedTuple):
    """Parsed components of an immutable image reference."""

    raw_ref: str
    repository: str
    tag: Optional[str]
    digest: str


def parse_and_validate_image_reference(ref: str) -> ParsedImageRef:
    """
    Semantically parses and validates an image reference string.

    Supports:
      - [registry/][repository][:tag]@sha256:<64 hex>
      - [registry/][repository]@sha256:<64 hex>
    Supports registry hostnames with port numbers (e.g. localhost:5000/repo/img:tag@sha256:...)

    Rejects:
      - Tag-only references (e.g. ubuntu:22.04 without digest)
      - Mutable tags like :latest without digest
      - Missing or invalid SHA256 digests
      - Malformed image reference strings
    """
    if not ref or not isinstance(ref, str):
        raise ImageResolutionError("Image reference must be a non-empty string")

    ref_str = ref.strip()

    # Must contain @sha256:
    if "@sha256:" not in ref_str:
        raise ImageResolutionError(
            f"Image reference '{ref}' is missing mandatory '@sha256:' digest"
        )

    parts = ref_str.rsplit("@sha256:", 1)
    name_part = parts[0].strip()
    digest_part = parts[1].strip().lower()

    if not name_part:
        raise ImageResolutionError(f"Image reference '{ref}' is missing repository name")

    # Validate 64 hex characters for digest
    if not re.match(r"^[a-f0-9]{64}$", digest_part):
        raise ImageResolutionError(
            f"Invalid SHA-256 digest in image reference '{ref}': "
            f"expected 64 hexadecimal characters, got '{digest_part}'"
        )

    # Parse name_part into repository and optional tag
    # Care must be taken not to confuse a host port (e.g. localhost:5000/repo) with a tag
    last_slash_idx = name_part.rfind("/")
    if last_slash_idx != -1:
        domain_and_path = name_part[:last_slash_idx]
        image_name_and_tag = name_part[last_slash_idx + 1 :]
    else:
        domain_and_path = ""
        image_name_and_tag = name_part

    if ":" in image_name_and_tag:
        name_sub, tag_sub = image_name_and_tag.rsplit(":", 1)
        if not name_sub or not tag_sub:
            raise ImageResolutionError(f"Malformed image name/tag in reference '{ref}'")
        repository = (domain_and_path + "/" + name_sub).lstrip("/") if domain_and_path else name_sub
        tag = tag_sub
    else:
        repository = name_part
        tag = None

    if tag == "latest" and "@sha256:" not in ref_str:
        raise ImageResolutionError("Mutable tag ':latest' without immutable digest is prohibited")

    return ParsedImageRef(
        raw_ref=ref_str,
        repository=repository,
        tag=tag,
        digest=digest_part,
    )


def verify_image_manifest_digest(
    docker_client, requested_digest: str, repo_digests: Optional[List[str]]
) -> bool:
    """
    Verifies daemon-resolved image RepoDigests contains requested SHA256 manifest digest.

    Does NOT accept an arbitrary Docker config/image ID digest as proof of manifest resolution.
    Must match against RepoDigests.
    """
    clean_requested = requested_digest.strip().lower()
    if clean_requested.startswith("sha256:"):
        clean_requested = clean_requested[7:]

    if not repo_digests:
        return False

    target_pattern = f"@sha256:{clean_requested}"
    for repo_digest in repo_digests:
        if repo_digest.strip().lower().endswith(target_pattern):
            return True

    return False
