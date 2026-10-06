"""
SCM URL Metadata Validator
"""

from typing import Optional
from urllib.parse import urlparse

from provenanceguard.builders.isolated.exceptions import SCMValidationError
from provenanceguard.builders.isolated.models import SCMMetadata


def validate_scm_url(
    scm_url: str, commit_sha: str, branch: Optional[str] = None, tag: Optional[str] = None
) -> SCMMetadata:
    """
    Validates SCM URL metadata for provenance tracking.

    Rejects embedded user credentials or userinfo.
    Normalizes URL string.
    Does NOT perform network access or git cloning operations.
    """
    if not scm_url or not isinstance(scm_url, str) or not scm_url.strip():
        raise SCMValidationError("SCM URL cannot be empty")

    url_str = scm_url.strip()

    # Check for git@ SCP-style URLs
    if url_str.startswith("git@"):
        # Check for password/userinfo in SCP style git@host:user/repo.git
        if ":" in url_str:
            host_part = url_str.split(":", 1)[0]
            if "@" in host_part:
                user_sub = host_part.split("@", 1)[0]
                if user_sub != "git":
                    raise SCMValidationError(
                        "SCM URL must not contain embedded user credentials or userinfo"
                    )
        normalized_url = url_str
    else:
        # Standard URL parsing
        try:
            parsed = urlparse(url_str)
        except Exception as e:
            raise SCMValidationError(f"Invalid SCM URL format: {e}") from e

        if not parsed.scheme:
            raise SCMValidationError(
                "SCM URL must include a valid protocol scheme (https, ssh, etc.)"
            )

        if parsed.username or parsed.password:
            raise SCMValidationError(
                "SCM URL must not contain embedded user credentials or userinfo"
            )

        if "@" in parsed.netloc and not parsed.netloc.startswith("git@"):
            raise SCMValidationError(
                "SCM URL must not contain embedded user credentials or userinfo"
            )

        # Normalize URL (lowercase scheme and netloc)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        normalized_url = f"{scheme}://{netloc}{parsed.path}"
        if parsed.query:
            normalized_url += f"?{parsed.query}"

    return SCMMetadata(
        scm_url=normalized_url,
        commit_sha=commit_sha,
        branch=branch,
        tag=tag,
    )
