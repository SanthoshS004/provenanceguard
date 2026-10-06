"""
GitHub Actions CI/CD Integration Runner for ProvenanceGuard (v1.1.0).

Streams generated software artifacts to ProvenanceGuard API Gateway, triggers
async zero-trust verification, polls ARQ worker status, and enforces fail-closed
release gating inside GitHub Actions workflows.
"""

import json
import os
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

MAX_ANNOTATIONS = 50
MAX_SUMMARY_BYTES = 64 * 1024


def sanitize_github_output(text: str) -> str:
    """Sanitizes text output to prevent GitHub Actions command injection."""
    clean = text.replace("\r", " ").replace("\n", " ")
    clean = clean.replace("::", "--").replace("%0A", " ").replace("%0D", " ")
    return clean.strip()


class ProvenanceGuardCIClient:
    """HTTP Client communicating with ProvenanceGuard API Gateway for CI/CD pipelines."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        project_id: Optional[str] = None,
        timeout: int = 30,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key.strip()
        self.project_id = project_id
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        return {
            "X-API-Key": self.api_key,
            "User-Agent": "ProvenanceGuard-CI-Runner/1.1.0",
        }

    def upload_artifact(
        self,
        file_path: str,
        name: Optional[str] = None,
        version: str = "1.0.0",
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Uploads binary artifact using multipart/form-data via HTTP POST."""
        path = Path(file_path)
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(f"Artifact file not found: {file_path}")

        target_project = project_id or self.project_id
        artifact_name = name or path.name

        boundary = f"----ProvenanceGuardBoundary{os.urandom(16).hex()}"
        body_bytes = bytearray()

        def add_field(field_name: str, value: str):
            nonlocal body_bytes
            body_bytes.extend(f"--{boundary}\r\n".encode("utf-8"))
            body_bytes.extend(f'Content-Disposition: form-data; name="{field_name}"\r\n\r\n'.encode("utf-8"))
            body_bytes.extend(f"{value}\r\n".encode("utf-8"))

        if target_project:
            add_field("project_id", target_project)
        add_field("name", artifact_name)
        add_field("version", version)

        # File Part
        body_bytes.extend(f"--{boundary}\r\n".encode("utf-8"))
        body_bytes.extend(
            f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'.encode("utf-8")
        )
        body_bytes.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        with open(path, "rb") as f:
            body_bytes.extend(f.read())
        body_bytes.extend(b"\r\n")
        body_bytes.extend(f"--{boundary}--\r\n".encode("utf-8"))

        headers = self._headers()
        headers["Content-Type"] = f"multipart/form-data; boundary={boundary}"

        url = f"{self.api_url}/api/v1/artifacts/upload"
        req = urllib.request.Request(url, data=bytes(body_bytes), headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data
        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Artifact upload HTTP {err.code}: {err_body}") from err
        except Exception as err:
            raise RuntimeError(f"Artifact upload request failed: {err}") from err

    def submit_verification(
        self,
        org_id: str,
        project_id: str,
        production_artifact_id: str,
        reference_artifact_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submits verification job request to ProvenanceGuard API."""
        payload = {
            "organization_id": org_id,
            "project_id": project_id,
            "production_artifact_id": production_artifact_id,
        }
        if reference_artifact_id:
            payload["reference_artifact_id"] = reference_artifact_id

        headers = self._headers()
        headers["Content-Type"] = "application/json"

        url = f"{self.api_url}/api/v1/verifications"
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            err_body = err.read().decode("utf-8", errors="ignore")
            raise RuntimeError(f"Verification submission HTTP {err.code}: {err_body}") from err

    def poll_verification(
        self, run_id: str, max_seconds: int = 60, poll_interval: float = 1.0
    ) -> Dict[str, Any]:
        """Polls verification run until status becomes SUCCEEDED, COMPLETED, or FAILED."""
        headers = self._headers()
        url = f"{self.api_url}/api/v1/verifications/{run_id}"

        start_time = time.time()
        while time.time() - start_time < max_seconds:
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    st = data.get("status", "")
                    if st in ("SUCCEEDED", "COMPLETED", "FAILED"):
                        return data
            except Exception:
                pass
            time.sleep(poll_interval)

        raise TimeoutError(f"Verification run '{run_id}' timed out after {max_seconds}s.")


class GitHubCIRunner:
    """Orchestrates end-to-end GitHub Actions workflow verification step."""

    def run(self, env: Optional[Dict[str, str]] = None) -> int:
        target_env = env if env is not None else dict(os.environ)

        api_url = target_env.get("PG_API_URL") or target_env.get("INPUT_PROVENANCEGUARD_URL") or "http://127.0.0.1:8000"
        api_key = target_env.get("PG_API_KEY") or target_env.get("INPUT_API_KEY")
        artifact_path = target_env.get("PG_ARTIFACT_PATH") or target_env.get("INPUT_ARTIFACT")
        project_id = target_env.get("PG_PROJECT_ID") or target_env.get("INPUT_PROJECT_ID")
        version = target_env.get("PG_VERSION") or target_env.get("INPUT_VERSION") or "1.0.0"

        # GitHub Metadata Context
        repo = target_env.get("GITHUB_REPOSITORY", "unknown/repo")
        commit_sha = target_env.get("GITHUB_SHA", "unknown_commit")
        ref_name = target_env.get("GITHUB_REF_NAME", "main")
        workflow = target_env.get("GITHUB_WORKFLOW", "CI Pipeline")
        run_id = target_env.get("GITHUB_RUN_ID", "0")

        if not api_key:
            sys.stderr.write("::error::Configuration Error: Required 'PG_API_KEY' secret is missing\n")
            return 2
        if not artifact_path:
            sys.stderr.write("::error::Configuration Error: Required 'PG_ARTIFACT_PATH' is missing\n")
            return 2

        client = ProvenanceGuardCIClient(api_url=api_url, api_key=api_key, project_id=project_id)

        try:
            sys.stdout.write(f"Uploading artifact '{artifact_path}' to ProvenanceGuard...\n")
            art_resp = client.upload_artifact(file_path=artifact_path, version=version, project_id=project_id)

            art_id = art_resp["id"]
            org_id = art_resp["organization_id"]
            resolved_proj_id = art_resp["project_id"]
            sha256 = art_resp["digest_sha256"]

            sys.stdout.write(f"Artifact uploaded successfully! ID: {art_id} | SHA-256: {sha256}\n")
            sys.stdout.write("Submitting zero-trust verification run request...\n")

            ver_resp = client.submit_verification(
                org_id=org_id,
                project_id=resolved_proj_id,
                production_artifact_id=art_id,
            )

            run_id_val = ver_resp["verification_run_id"]
            sys.stdout.write(f"Verification Run queued: {run_id_val}. Polling ARQ worker status...\n")

            result = client.poll_verification(run_id=run_id_val, max_seconds=30)
            decision = result.get("decision", "BLOCK")
            risk_score = result.get("risk_score", 0)
            run_status = result.get("status", "UNKNOWN")

            sys.stdout.write(f"\n==================================================\n")
            sys.stdout.write(f"PROVENANCEGUARD VERIFICATION RESULT: {decision}\n")
            sys.stdout.write(f"Risk Score: {risk_score} / 100\n")
            sys.stdout.write(f"Repository: {repo} | Branch: {ref_name} | Commit: {commit_sha[:7]}\n")
            sys.stdout.write(f"Workflow: {workflow} | Run ID: {run_id}\n")
            sys.stdout.write(f"==================================================\n\n")

            # Write Step Summary
            summary_path = target_env.get("GITHUB_STEP_SUMMARY")
            if summary_path:
                lines = [
                    "## ProvenanceGuard Supply-Chain Verification",
                    f"- **Decision**: `{decision}`",
                    f"- **Risk Score**: `{risk_score} / 100`",
                    f"- **Artifact SHA-256**: `{sha256}`",
                    f"- **Source Commit**: `{commit_sha[:7]}` (`{repo}` on `{ref_name}`)",
                    f"- **CI Workflow**: `{workflow}` (Run #{run_id})",
                ]
                try:
                    with open(summary_path, "a", encoding="utf-8") as f:
                        f.write("\n".join(lines) + "\n")
                except Exception:
                    pass

            if decision in ("PASS", "PASS_WITH_WARNING"):
                sys.stdout.write("::notice::ProvenanceGuard verification PASSED cleanly.\n")
                return 0
            else:
                sys.stderr.write(
                    f"::error title=Verification Blocked::ProvenanceGuard Policy Engine rejected artifact. Decision: BLOCK, Risk Score: {risk_score}/100\n"
                )
                return 1

        except Exception as err:
            clean_err = sanitize_github_output(str(err))
            sys.stderr.write(f"::error::ProvenanceGuard CI Error: {clean_err}\n")
            return 2


def main():
    runner = GitHubCIRunner()
    sys.exit(runner.run())


if __name__ == "__main__":
    main()
