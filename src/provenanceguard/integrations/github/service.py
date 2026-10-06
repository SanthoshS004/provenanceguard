"""GitHub API Integration Service for ProvenanceGuard.

Handles GitHub REST API communication for PULL-based artifact discovery, repository validation,
commit inspection, and safe artifact extraction without executing arbitrary binaries.
Includes safe Local Demonstration Mode fallback.
"""

import io
import json
import os
import urllib.error
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

MAX_ARTIFACT_ZIP_BYTES = 50 * 1024 * 1024  # 50 MB zip limit
MAX_EXTRACTED_BYTES = 100 * 1024 * 1024     # 100 MB uncompressed limit
MAX_ZIP_ENTRIES = 100                        # Max file count limit


class GitHubIntegrationError(Exception):
    """Base exception for GitHub Integration errors."""
    pass


class GitHubAuthenticationError(GitHubIntegrationError):
    """Raised when GITHUB_TOKEN is invalid or unauthorized."""
    pass


class GitHubResourceNotFoundError(GitHubIntegrationError):
    """Raised when repository, workflow run, or artifact is not found."""
    pass


class GitHubIntegrationService:
    """Communicates with GitHub REST API for repository & artifact discovery."""

    def __init__(self, token: Optional[str] = None):
        # Always prioritize passed token, falling back strictly to environment variable
        self.token = (token or os.getenv("GITHUB_TOKEN", "")).strip()

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "ProvenanceGuard-Backend/1.0.0",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def validate_credentials(self) -> Dict[str, Any]:
        """Validates GITHUB_TOKEN by fetching user profile from GitHub API."""
        if not self.token:
            raise GitHubAuthenticationError("NO_GITHUB_TOKEN: GITHUB_TOKEN environment variable is not configured.")

        url = "https://api.github.com/user"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "valid": True,
                    "user": data.get("login"),
                    "name": data.get("name"),
                }
        except urllib.error.HTTPError as err:
            if err.code in (401, 403):
                raise GitHubAuthenticationError("INVALID_GITHUB_TOKEN: GitHub authentication failed.") from err
            raise GitHubIntegrationError(f"GitHub API Error HTTP {err.code}") from err
        except Exception as err:
            raise GitHubIntegrationError(f"Failed to communicate with GitHub API: {str(err)}") from err

    def get_repository_info(self, repo: str) -> Dict[str, Any]:
        """Fetches repository metadata for 'owner/repo'."""
        if not repo or "/" not in repo:
            raise ValueError("Repository must be in 'owner/repo' format.")

        url = f"https://api.github.com/repos/{repo}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "full_name": data.get("full_name"),
                    "default_branch": data.get("default_branch", "main"),
                    "private": data.get("private", False),
                    "html_url": data.get("html_url"),
                }
        except urllib.error.HTTPError as err:
            if err.code == 404:
                raise GitHubResourceNotFoundError(f"REPOSITORY_NOT_FOUND: Repository '{repo}' not found or access denied.") from err
            elif err.code in (401, 403):
                raise GitHubAuthenticationError("GitHub authentication required to access repository.") from err
            raise GitHubIntegrationError(f"GitHub API Error HTTP {err.code}") from err
        except Exception as err:
            raise GitHubIntegrationError(f"Failed to fetch repository metadata: {str(err)}") from err

    def get_latest_commit(self, repo: str, branch: str = "main") -> Dict[str, Any]:
        """Fetches latest commit SHA and details for given branch."""
        url = f"https://api.github.com/repos/{repo}/commits/{branch}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                commit = data.get("commit", {})
                return {
                    "sha": data.get("sha"),
                    "short_sha": data.get("sha", "")[:7],
                    "message": commit.get("message", "").split("\n")[0],
                    "author": commit.get("author", {}).get("name"),
                    "date": commit.get("author", {}).get("date"),
                }
        except urllib.error.HTTPError as err:
            if err.code == 404:
                raise GitHubResourceNotFoundError(f"Branch or commit '{branch}' not found for repository '{repo}'.") from err
            raise GitHubIntegrationError(f"GitHub API Error HTTP {err.code}") from err
        except Exception as err:
            raise GitHubIntegrationError(f"Failed to fetch latest commit: {str(err)}") from err

    def get_latest_workflow_run(self, repo: str, branch: str = "main") -> Dict[str, Any]:
        """Finds latest completed GitHub Actions workflow run for branch."""
        url = f"https://api.github.com/repos/{repo}/actions/runs?branch={branch}&status=completed&per_page=10"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                runs = data.get("workflow_runs", [])
                if not runs:
                    raise GitHubResourceNotFoundError(f"NO_WORKFLOW: No completed workflow runs found for '{repo}' on branch '{branch}'.")
                
                # Pick latest successful run if possible, else first completed
                successful = [r for r in runs if r.get("conclusion") == "success"]
                target_run = successful[0] if successful else runs[0]

                return {
                    "id": str(target_run.get("id")),
                    "name": target_run.get("name"),
                    "run_number": str(target_run.get("run_number")),
                    "status": target_run.get("status"),
                    "conclusion": target_run.get("conclusion"),
                    "head_sha": target_run.get("head_sha"),
                    "head_branch": target_run.get("head_branch"),
                    "artifacts_url": target_run.get("artifacts_url"),
                    "updated_at": target_run.get("updated_at"),
                }
        except urllib.error.HTTPError as err:
            if err.code == 404:
                raise GitHubResourceNotFoundError(f"NO_WORKFLOW: GitHub Actions workflows not found for repository '{repo}'.") from err
            raise GitHubIntegrationError(f"GitHub API Error HTTP {err.code}") from err
        except Exception as err:
            if isinstance(err, GitHubIntegrationError):
                raise
            raise GitHubIntegrationError(f"Failed to fetch workflow runs: {str(err)}") from err

    def get_workflow_artifacts(self, repo: str, run_id: str) -> List[Dict[str, Any]]:
        """Retrieves list of build artifacts for workflow run."""
        url = f"https://api.github.com/repos/{repo}/actions/runs/{run_id}/artifacts"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                artifacts = data.get("artifacts", [])
                if not artifacts:
                    raise GitHubResourceNotFoundError(f"NO_ARTIFACT: No build artifacts found for workflow run '{run_id}'.")
                
                res = []
                for art in artifacts:
                    res.append({
                        "id": str(art.get("id")),
                        "name": art.get("name"),
                        "size_in_bytes": art.get("size_in_bytes"),
                        "archive_download_url": art.get("archive_download_url"),
                        "expired": art.get("expired", False),
                    })
                return res
        except urllib.error.HTTPError as err:
            if err.code == 404:
                raise GitHubResourceNotFoundError(f"Artifacts not found for run '{run_id}'.") from err
            raise GitHubIntegrationError(f"GitHub API Error HTTP {err.code}") from err
        except Exception as err:
            if isinstance(err, GitHubIntegrationError):
                raise
            raise GitHubIntegrationError(f"Failed to fetch workflow artifacts: {str(err)}") from err

    def download_and_extract_artifact(self, repo: str, artifact_id: str) -> Tuple[bytes, str]:
        """Safely downloads GitHub Actions artifact archive and extracts the binary payload.
        
        Validates zip boundaries, enforces size/count limits, and never executes files.
        Returns tuple of (file_bytes, filename).
        """
        if not self.token:
            raise GitHubAuthenticationError("NO_GITHUB_TOKEN: Authentication required to download build artifacts.")

        url = f"https://api.github.com/repos/{repo}/actions/artifacts/{artifact_id}/zip"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                zip_bytes = resp.read()
        except urllib.error.HTTPError as err:
            if err.code == 404:
                raise GitHubResourceNotFoundError(f"DOWNLOAD_FAILED: Artifact archive '{artifact_id}' not found or expired.") from err
            raise GitHubIntegrationError(f"DOWNLOAD_FAILED: Failed to download artifact (HTTP {err.code})") from err
        except Exception as err:
            raise GitHubIntegrationError(f"DOWNLOAD_FAILED: Artifact download error: {str(err)}") from err

        if len(zip_bytes) > MAX_ARTIFACT_ZIP_BYTES:
            raise ValueError(f"Artifact zip archive size ({len(zip_bytes)} bytes) exceeds limit of {MAX_ARTIFACT_ZIP_BYTES} bytes.")

        try:
            with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
                infolist = zf.infolist()
                if len(infolist) > MAX_ZIP_ENTRIES:
                    raise ValueError(f"Artifact archive contains too many files ({len(infolist)} > {MAX_ZIP_ENTRIES}).")

                # Total size check
                total_uncompressed = sum(info.file_size for info in infolist)
                if total_uncompressed > MAX_EXTRACTED_BYTES:
                    raise ValueError(f"Uncompressed artifact size exceeds limit ({total_uncompressed} bytes).")

                # Filter regular files and prevent zip slip
                valid_entries = []
                for info in infolist:
                    if info.is_dir() or ".." in info.filename or info.filename.startswith("/"):
                        continue
                    valid_entries.append(info)

                if not valid_entries:
                    raise ValueError("Artifact archive contains no valid files.")

                # Pick primary entry (prefer .bin, .elf, .tar, .zip, or first non-text file)
                target_info = valid_entries[0]
                for info in valid_entries:
                    ext = os.path.splitext(info.filename)[1].lower()
                    if ext in (".bin", ".elf", ".so", ".exe", ".tar", ".gz", ".apk"):
                        target_info = info
                        break

                content = zf.read(target_info.filename)
                filename = os.path.basename(target_info.filename)
                return content, filename
        except zipfile.BadZipFile as bzf:
            # If not a zip archive, treat raw content as binary artifact payload directly
            return zip_bytes, f"artifact-{artifact_id}.bin"

    def demo_collect_artifact(self) -> Tuple[bytes, str, Dict[str, str]]:
        """Returns safe Local Demonstration fixture artifact with clear [DEMO] Git metadata."""
        fixture_path = os.path.join(os.path.dirname(__file__), "../../../..", "test-upload-elf.bin")
        if not os.path.exists(fixture_path):
            # Safe fallback byte payload if fixture file absent
            content = b"\x7fELF\x02\x01\x01\x00ProvenanceGuardDemoFixtureBinaryPayload"
        else:
            with open(fixture_path, "rb") as f:
                content = f.read()

        git_meta = {
            "repository": "demo-org/provenanceguard-demo",
            "branch": "main",
            "commit_sha": "a1b2c3d4e5f67890123456789abcdef012345678",
            "workflow_name": "[DEMO] Build & Security Verification",
            "workflow_run_id": "99999",
            "build_number": "1",
            "artifact_name": "provenanceguard-demo-v1.0.0.elf",
            "artifact_type": "BUILD_ARTIFACT",
            "is_demo": "true",
        }
        return content, "provenanceguard-demo-v1.0.0.elf", git_meta
