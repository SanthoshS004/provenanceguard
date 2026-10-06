"""
Jenkins Pipeline Integration Adapter for ProvenanceGuard.

Thin Jenkins pipeline runner wrapper.
Contains ZERO independent policy or risk calculation logic.
Delegates directly to VerificationAppService and maps exit codes (0, 1, 2, 3).
"""

import os
import sys
from typing import Dict, Optional

from provenanceguard.apps.cli.exit_codes import ExitCode
from provenanceguard.apps.services.verification_service import VerificationAppService
from provenanceguard.core.policy.policy_engine import (
    PolicyConfigError,
    PolicyDecision,
)


class JenkinsPipelineRunner:
    """
    Jenkins Pipeline Runner wrapper for ProvenanceGuard.
    """

    def __init__(self, service: Optional[VerificationAppService] = None):
        self.service = service or VerificationAppService()

    def run(self, env: Optional[Dict[str, str]] = None) -> int:
        """
        Executes Jenkins Pipeline verification step and returns exit code (0, 1, 2, 3).
        """
        target_env = env if env is not None else dict(os.environ)

        artifact_path = target_env.get("ARTIFACT_PATH") or target_env.get("INPUT_ARTIFACT")
        policy_path = target_env.get("POLICY_PATH") or target_env.get("INPUT_POLICY")
        reference_path = target_env.get("REFERENCE_PATH") or target_env.get("INPUT_REFERENCE")
        attestation_path = target_env.get("ATTESTATION_PATH") or target_env.get("INPUT_ATTESTATION")
        sbom_path = target_env.get("SBOM_PATH") or target_env.get("INPUT_SBOM")

        if not artifact_path:
            sys.stderr.write(
                "[Jenkins] ERROR: Required environment variable ARTIFACT_PATH is missing\n"
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

            sys.stdout.write(f"[Jenkins] Verification Decision: {result.decision.value}\n")
            sys.stdout.write(f"[Jenkins] Risk Score: {result.risk_score} / 100\n")
            sys.stdout.write(f"[Jenkins] Rationale: {result.rationale}\n")

            if result.decision in (PolicyDecision.PASS, PolicyDecision.PASS_WITH_WARNING):
                return ExitCode.PASS
            else:
                sys.stderr.write(
                    "[Jenkins] RELEASE BLOCKED: Verification policy decision is BLOCK\n"
                )
                return ExitCode.BLOCK

        except PolicyConfigError as pce:
            sys.stderr.write(f"[Jenkins] ERROR: Policy Configuration Error: {str(pce)}\n")
            return ExitCode.CONFIG_ERROR
        except (FileNotFoundError, ValueError) as ve:
            sys.stderr.write(f"[Jenkins] ERROR: Input Configuration Error: {str(ve)}\n")
            return ExitCode.CONFIG_ERROR
        except Exception as e:
            sys.stderr.write(f"[Jenkins] ERROR: Unexpected System Failure: {str(e)}\n")
            return ExitCode.SYSTEM_ERROR


def main():
    runner = JenkinsPipelineRunner()
    exit_code = runner.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
