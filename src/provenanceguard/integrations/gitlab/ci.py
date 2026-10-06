"""
GitLab CI Integration Adapter for ProvenanceGuard.

Generates official CodeClimate-compatible GitLab Code Quality JSON report array.
Enforces fail-closed release blocking inside GitLab CI pipelines.
"""

import hashlib
import json
import os
import sys
from typing import Dict, List, Optional

from provenanceguard.apps.cli.exit_codes import ExitCode
from provenanceguard.apps.services.verification_service import VerificationAppService
from provenanceguard.core.policy.policy_engine import (
    PolicyConfigError,
    PolicyDecision,
    PolicyEvaluationResult,
)


class GitLabCIRunner:
    """
    GitLab CI Runner wrapper for ProvenanceGuard.
    """

    def __init__(self, service: Optional[VerificationAppService] = None):
        self.service = service or VerificationAppService()

    def generate_code_quality_report(
        self, result: PolicyEvaluationResult, artifact_path: str
    ) -> List[Dict]:
        """
        Generates official GitLab Code Quality report array adhering to CodeClimate schema.
        """
        report: List[Dict] = []
        severity_map = {
            "CRITICAL": "critical",
            "HIGH": "major",
            "MEDIUM": "minor",
            "LOW": "info",
            "INFO": "info",
        }

        for finding in result.findings:
            raw_fingerprint = f"{finding.id}:{finding.subject}:{finding.explanation}".encode(
                "utf-8"
            )
            fingerprint = hashlib.sha256(raw_fingerprint).hexdigest()

            item = {
                "description": finding.explanation,
                "check_name": finding.id,
                "fingerprint": fingerprint,
                "severity": severity_map.get(finding.severity.value, "minor"),
                "location": {
                    "path": artifact_path,
                    "lines": {"begin": 1},
                },
            }
            report.append(item)

        return report

    def run(self, env: Optional[Dict[str, str]] = None) -> int:
        """
        Executes GitLab CI verification and outputs Code Quality JSON if specified.
        Returns exit code (0, 1, 2, 3).
        """
        target_env = env if env is not None else dict(os.environ)

        artifact_path = target_env.get("ARTIFACT_PATH") or target_env.get("INPUT_ARTIFACT")
        policy_path = target_env.get("POLICY_PATH") or target_env.get("INPUT_POLICY")
        reference_path = target_env.get("REFERENCE_PATH") or target_env.get("INPUT_REFERENCE")
        attestation_path = target_env.get("ATTESTATION_PATH") or target_env.get("INPUT_ATTESTATION")
        sbom_path = target_env.get("SBOM_PATH") or target_env.get("INPUT_SBOM")
        report_output_path = target_env.get("GL_CODE_QUALITY_REPORT", "gl-code-quality-report.json")

        if not artifact_path:
            sys.stderr.write(
                "GitLab CI Error: Required environment variable ARTIFACT_PATH is missing\n"
            )
            return ExitCode.CONFIG_ERROR

        try:
            result = self.service.verify_artifact(
                artifact_path=artifact_path,
                policy_path=policy_path,
                reference_path=reference_path,
                attestation_path=attestation_path,
                sbom_path=sbom_path,
            )

            # Generate and write GitLab Code Quality JSON report
            cq_report = self.generate_code_quality_report(result, artifact_path)
            if report_output_path:
                try:
                    with open(report_output_path, "w", encoding="utf-8") as f:
                        json.dump(cq_report, f, indent=2)
                except Exception as e:
                    sys.stderr.write(
                        f"Warning: Failed to write Code Quality JSON report: {str(e)}\n"
                    )

            sys.stdout.write(f"GitLab CI Verification Decision: {result.decision.value}\n")
            sys.stdout.write(f"Risk Score: {result.risk_score} / 100\n")

            if result.decision in (PolicyDecision.PASS, PolicyDecision.PASS_WITH_WARNING):
                return ExitCode.PASS
            else:
                return ExitCode.BLOCK

        except PolicyConfigError as pce:
            sys.stderr.write(f"GitLab CI Policy Error: {str(pce)}\n")
            return ExitCode.CONFIG_ERROR
        except (FileNotFoundError, ValueError) as ve:
            sys.stderr.write(f"GitLab CI Configuration Error: {str(ve)}\n")
            return ExitCode.CONFIG_ERROR
        except Exception as e:
            sys.stderr.write(f"GitLab CI Unexpected System Error: {str(e)}\n")
            return ExitCode.SYSTEM_ERROR


def main():
    runner = GitLabCIRunner()
    exit_code = runner.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
