"""
ProvenanceGuard CLI Command Application
"""

import json
import sys
from pathlib import Path

import click

from provenanceguard import __version__
from provenanceguard.analyzers.elf.parser import StaticELFParser
from provenanceguard.apps.cli.exit_codes import ExitCode
from provenanceguard.apps.services.verification_service import VerificationAppService
from provenanceguard.core.policy.policy_engine import (
    PolicyConfigError,
    PolicyDecision,
    PolicyEngine,
)
from provenanceguard.core.verification.provenance_models import (
    CombinedAttestationVerificationReport,
)


@click.group()
@click.version_option(version=__version__, prog_name="provenanceguard")
def cli():
    """ProvenanceGuard Enterprise Zero-Trust Verification CLI."""
    pass


@cli.command(name="verify")
@click.option(
    "--artifact", required=True, type=click.Path(exists=True), help="Path to production artifact"
)
@click.option(
    "--policy", required=False, type=click.Path(exists=True), help="Path to policy YAML file"
)
@click.option(
    "--reference",
    required=False,
    type=click.Path(exists=True),
    help="Path to reference artifact",
)
@click.option(
    "--attestation",
    required=False,
    type=click.Path(exists=True),
    help="Path to JSON attestation / Sigstore bundle file",
)
@click.option(
    "--sbom",
    required=False,
    type=click.Path(exists=True),
    help="Path to SBOM JSON document",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output explainable decision as JSON object",
)
def verify(artifact, policy, reference, attestation, sbom, json_output):
    """Verify production artifact against policy, reference build, attestation, and SBOM."""
    try:
        service = VerificationAppService()
        policy_result = service.verify_artifact(
            artifact_path=artifact,
            policy_path=policy,
            reference_path=reference,
            attestation_path=attestation,
            sbom_path=sbom,
        )

        if json_output:
            click.echo(policy_result.model_dump_json(indent=2))
        else:
            click.echo(f"ProvenanceGuard Verification Decision: {policy_result.decision.value}")
            click.echo(f"Policy Name: {policy_result.policy_name}")
            click.echo(
                f"Risk Score: {policy_result.risk_score} / 100 "
                f"(Raw: {policy_result.raw_risk_score})"
            )
            click.echo(f"Rationale: {policy_result.rationale}")
            if policy_result.findings:
                click.echo(f"Findings ({len(policy_result.findings)}):")
                for f in policy_result.findings:
                    click.echo(f"  - [{f.severity.value}] {f.id}: {f.explanation}")

        # Map Decision to Exit Code
        if policy_result.decision in (PolicyDecision.PASS, PolicyDecision.PASS_WITH_WARNING):
            sys.exit(ExitCode.PASS)
        else:
            sys.exit(ExitCode.BLOCK)

    except SystemExit:
        raise
    except (PolicyConfigError, FileNotFoundError, ValueError, json.JSONDecodeError) as e:
        err_msg = f"Configuration Error: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.CONFIG_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.CONFIG_ERROR)
    except Exception as e:
        err_msg = f"Unexpected System Failure: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.SYSTEM_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.SYSTEM_ERROR)


@cli.command(name="inspect")
@click.option(
    "--artifact", required=True, type=click.Path(exists=True), help="Path to artifact file"
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output inspection details as JSON object",
)
def inspect(artifact, json_output):
    """Inspect binary metadata, section characteristics, and cryptographic digests."""
    try:
        art_path = Path(artifact)
        if not art_path.exists():
            raise FileNotFoundError(f"Artifact file not found: {artifact}")

        from provenanceguard.core.artifacts.detector import detect_media_type_from_stream
        from provenanceguard.core.common.crypto import calculate_stream_digests
        from provenanceguard.core.domain.enums import DigestAlgorithm

        with open(art_path, "rb") as f:
            digests_list, size_bytes = calculate_stream_digests(f)
            f.seek(0)
            media_type = detect_media_type_from_stream(f)

        sha256_val = next(
            (d.value for d in digests_list if d.algorithm == DigestAlgorithm.SHA256), ""
        )
        sha512_val = next(
            (d.value for d in digests_list if d.algorithm == DigestAlgorithm.SHA512), ""
        )

        report_data = {
            "file_name": art_path.name,
            "media_type": media_type.value if hasattr(media_type, "value") else str(media_type),
            "size_bytes": size_bytes,
            "sha256": sha256_val,
            "sha512": sha512_val,
        }

        # If ELF binary, run static ELF analyzer
        if art_path.suffix == ".bin" or report_data["media_type"] in (
            "application/vnd.elf",
            "application/x-executable",
        ):
            try:
                elf_parser = StaticELFParser()
                elf_report = elf_parser.parse_file(str(art_path))
                report_data["elf_architecture"] = elf_report.header.architecture
                report_data["elf_is_stripped"] = elf_report.header.is_stripped
                report_data["elf_sections_count"] = len(elf_report.sections)
                report_data["elf_functions_count"] = len(elf_report.symbol_derived_functions)
            except Exception:
                pass

        if json_output:
            click.echo(json.dumps(report_data, indent=2))
        else:
            click.echo(f"Inspecting artifact: {art_path.name}")
            click.echo(f"  Media Type: {report_data['media_type']}")
            click.echo(f"  Size: {report_data['size_bytes']} bytes")
            click.echo(f"  SHA-256: {report_data['sha256']}")
            if "elf_architecture" in report_data:
                click.echo(f"  Architecture: {report_data['elf_architecture']}")
                click.echo(f"  Is Stripped: {report_data['elf_is_stripped']}")
                click.echo(f"  Sections: {report_data['elf_sections_count']}")
                click.echo(f"  Functions: {report_data['elf_functions_count']}")

        sys.exit(ExitCode.PASS)

    except SystemExit:
        raise
    except (FileNotFoundError, ValueError, PermissionError) as e:
        err_msg = f"Configuration Error: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.CONFIG_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.CONFIG_ERROR)
    except Exception as e:
        err_msg = f"Unexpected System Failure: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.SYSTEM_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.SYSTEM_ERROR)


@cli.group(name="policy")
def policy_group():
    """Policy management commands."""
    pass


@policy_group.command(name="validate")
@click.option(
    "--policy", required=True, type=click.Path(exists=True), help="Path to policy YAML file"
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output validation status as JSON object",
)
def policy_validate(policy, json_output):
    """Validate policy YAML schema and threshold configuration."""
    try:
        pol_path = Path(policy)
        if not pol_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy}")

        with open(pol_path, "r", encoding="utf-8") as f:
            yaml_content = f.read()

        policy_config = PolicyEngine.load_policy_from_yaml(yaml_content)

        res_data = {
            "status": "VALID",
            "policy_name": policy_config.name,
            "policy_version": policy_config.version,
            "warning_threshold": policy_config.warning_threshold,
            "block_threshold": policy_config.block_threshold,
        }

        if json_output:
            click.echo(json.dumps(res_data, indent=2))
        else:
            click.echo(f"Policy '{policy_config.name}' (v{policy_config.version}) is VALID.")
            click.echo(f"  Warning Threshold: {policy_config.warning_threshold}")
            click.echo(f"  Block Threshold: {policy_config.block_threshold}")

        sys.exit(ExitCode.PASS)

    except SystemExit:
        raise
    except (PolicyConfigError, FileNotFoundError, PermissionError, ValueError) as e:
        err_msg = f"Policy Configuration Error: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.CONFIG_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.CONFIG_ERROR)
    except Exception as e:
        err_msg = f"Unexpected System Failure: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.SYSTEM_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.SYSTEM_ERROR)


@cli.group(name="provenance")
def provenance_group():
    """Attestation and provenance verification commands."""
    pass


@provenance_group.command(name="verify")
@click.option(
    "--attestation",
    required=True,
    type=click.Path(exists=True),
    help="Path to JSON attestation file",
)
@click.option(
    "--subject-digest",
    required=False,
    type=str,
    help="Expected target subject SHA-256 digest",
)
@click.option(
    "--json-output",
    is_flag=True,
    default=False,
    help="Output attestation verification report as JSON",
)
def provenance_verify(attestation, subject_digest, json_output):
    """Verify DSSE / SLSA / Sigstore attestation payload independently."""
    try:
        att_path = Path(attestation)
        if not att_path.exists():
            raise FileNotFoundError(f"Attestation file not found: {attestation}")

        with open(att_path, "r", encoding="utf-8") as f:
            raw_att = json.load(f)

        att_report = CombinedAttestationVerificationReport.model_validate(raw_att)

        # Check overall attestation validity
        is_valid = True
        reasons = []

        if att_report.dsse_report and not att_report.dsse_report.signature_verified:
            is_valid = False
            reasons.append("DSSE signature verification failed")

        if att_report.sigstore_report and not att_report.sigstore_report.certificate_chain_valid:
            is_valid = False
            reasons.append("Sigstore certificate chain validation failed")

        if subject_digest and att_report.slsa_report:
            corr = att_report.slsa_report.subject_correlation
            if corr.matching_mode != "EXACT_ONE_MATCH":
                is_valid = False
                reasons.append(
                    f"Subject correlation mode is '{corr.matching_mode}' (expected EXACT_ONE_MATCH)"
                )

        res_data = {
            "valid": is_valid,
            "reasons": reasons,
            "attestation_report": att_report.model_dump(),
        }

        if json_output:
            click.echo(json.dumps(res_data, indent=2))
        else:
            status_str = "VALID" if is_valid else "INVALID / FAILED"
            click.echo(f"Attestation Verification Status: {status_str}")
            if reasons:
                click.echo("Verification Failures:")
                for r in reasons:
                    click.echo(f"  - {r}")

        if is_valid:
            sys.exit(ExitCode.PASS)
        else:
            sys.exit(ExitCode.BLOCK)

    except SystemExit:
        raise
    except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
        err_msg = f"Attestation Configuration Error: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.CONFIG_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.CONFIG_ERROR)
    except Exception as e:
        err_msg = f"Unexpected System Failure: {str(e)}"
        if json_output:
            click.echo(json.dumps({"error": err_msg, "exit_code": int(ExitCode.SYSTEM_ERROR)}))
        else:
            click.echo(err_msg, err=True)
        sys.exit(ExitCode.SYSTEM_ERROR)


if __name__ == "__main__":
    cli()
