"""
GitHub Actions Integration Adapter for ProvenanceGuard.

Enforces zero-trust fail-closed release blocking inside GitHub Actions workflows.
Secured against workflow command injection and output payload overflow.
Pure Python implementation: ZERO shell subprocess execution.
"""

import os
import sys
from typing import Dict, Optional

from provenanceguard.apps.cli.exit_codes import ExitCode
from provenanceguard.apps.services.verification_service import VerificationAppService
from provenanceguard.core.policy.policy_engine import (
    PolicyConfigError,
    PolicyDecision,
    PolicyEvaluationResult,
)

MAX_GITHUB_ANNOTATIONS = 50
MAX_GITHUB_SUMMARY_BYTES = 64 * 1024  # 64 KB limit


def sanitize_github_command_value(text: str) -> str:
    """
    Sanitize text used in GitHub Action workflow command annotations.
    Prevents workflow command injection (%0A, %0D, :: delimiter escaping).
    Treats input strictly as untrusted data.
    """
    clean = text.replace("\r", " ").replace("\n", " ")
    clean = clean.replace("::", "--")
    clean = clean.replace("%0A", " ").replace("%0D", " ")
    return clean.strip()


class GitHubActionRunner:
    """
    GitHub Action Runner wrapper for ProvenanceGuard.
    """

    def __init__(self, service: Optional[VerificationAppService] = None):
        self.service = service or VerificationAppService()

    def run(self, env: Optional[Dict[str, str]] = None) -> int:
        """
        Executes GitHub Action verification using environment variables or passed dictionary.
        Returns strict exit code (0, 1, 2, 3).
        """
        target_env = env if env is not None else dict(os.environ)

        artifact_path = target_env.get("INPUT_ARTIFACT") or target_env.get("ARTIFACT_PATH")
        policy_path = target_env.get("INPUT_POLICY") or target_env.get("POLICY_PATH")
        reference_path = target_env.get("INPUT_REFERENCE") or target_env.get("REFERENCE_PATH")
        attestation_path = target_env.get("INPUT_ATTESTATION") or target_env.get("ATTESTATION_PATH")
        sbom_path = target_env.get("INPUT_SBOM") or target_env.get("SBOM_PATH")

        if not artifact_path:
            err_msg = "::error::GitHub Action Input Error: Required 'INPUT_ARTIFACT' is missing\n"
            sys.stderr.write(err_msg)
            return ExitCode.CONFIG_ERROR

        try:
            result: PolicyEvaluationResult = self.service.verify_artifact(
                artifact_path=artifact_path,
                policy_path=policy_path,
                reference_path=reference_path,
                attestation_path=attestation_path,
                sbom_path=sbom_path,
            )

            # Emit workflow annotations (capped at MAX_GITHUB_ANNOTATIONS)
            annotation_count = 0
            for finding in result.findings:
                if annotation_count >= MAX_GITHUB_ANNOTATIONS:
                    warn_msg = (
                        f"::warning::Annotation limit reached ({MAX_GITHUB_ANNOTATIONS}). "
                        "Remaining findings omitted.\n"
                    )
                    sys.stdout.write(warn_msg)
                    break

                command_type = (
                    "error" if finding.severity.value in ("CRITICAL", "HIGH") else "warning"
                )
                clean_title = sanitize_github_command_value(
                    f"[{finding.severity.value}] {finding.id}"
                )
                clean_msg = sanitize_github_command_value(finding.explanation)
                sys.stdout.write(f"::{command_type} title={clean_title}::{clean_msg}\n")
                annotation_count += 1

            # Emit Step Summary ($GITHUB_STEP_SUMMARY) if present
            summary_path = target_env.get("GITHUB_STEP_SUMMARY")
            if summary_path:
                score_str = f"`{result.risk_score} / 100` (Raw: `{result.raw_risk_score}`)"
                summary_lines = [
                    "## ProvenanceGuard Verification Summary",
                    f"- **Decision**: `{result.decision.value}`",
                    f"- **Policy**: `{result.policy_name}`",
                    f"- **Risk Score**: {score_str}",
                    f"- **Rationale**: {sanitize_github_command_value(result.rationale)}",
                    f"- **Total Findings**: `{len(result.findings)}`",
                ]

                summary_text = "\n".join(summary_lines) + "\n"
                summary_bytes = summary_text.encode("utf-8")[:MAX_GITHUB_SUMMARY_BYTES]
                try:
                    with open(summary_path, "ab") as f:
                        f.write(summary_bytes)
                except Exception:
                    pass

            if result.decision in (PolicyDecision.PASS, PolicyDecision.PASS_WITH_WARNING):
                return ExitCode.PASS
            else:
                return ExitCode.BLOCK

        except PolicyConfigError as pce:
            clean_err = sanitize_github_command_value(str(pce))
            sys.stderr.write(f"::error::Policy Configuration Error: {clean_err}\n")
            return ExitCode.CONFIG_ERROR
        except (FileNotFoundError, ValueError) as ve:
            clean_err = sanitize_github_command_value(str(ve))
            sys.stderr.write(f"::error::Input Configuration Error: {clean_err}\n")
            return ExitCode.CONFIG_ERROR
        except Exception as e:
            clean_err = sanitize_github_command_value(str(e))
            sys.stderr.write(f"::error::Unexpected System Error: {clean_err}\n")
            return ExitCode.SYSTEM_ERROR


def main():
    runner = GitHubActionRunner()
    exit_code = runner.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
