"""
Unit Tests for CLI verify command & Exit Code mapping (0, 1, 2, 3).
"""

from unittest.mock import patch

from click.testing import CliRunner

from provenanceguard.apps.cli.main import cli


def test_cli_verify_missing_artifact_returns_exit_2(tmp_path):
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--artifact", str(tmp_path / "non_existent.bin")])
    assert result.exit_code == 2


def test_cli_verify_valid_artifact_default_returns_exit_0(tmp_path):
    runner = CliRunner()
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    result = runner.invoke(cli, ["verify", "--artifact", str(art_file)])
    # Default policy (no rules set, score 30 for missing attestation -> PASS_WITH_WARNING -> exit 0)
    assert result.exit_code == 0
    assert "ProvenanceGuard Verification Decision" in result.output


def test_cli_verify_policy_block_returns_exit_1(tmp_path):
    runner = CliRunner()
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    policy_file = tmp_path / "block_policy.yaml"
    policy_file.write_text("require_valid_signature: true\n")

    result = runner.invoke(
        cli, ["verify", "--artifact", str(art_file), "--policy", str(policy_file)]
    )
    assert result.exit_code == 1
    assert "BLOCK" in result.output


def test_cli_verify_malformed_policy_returns_exit_2(tmp_path):
    runner = CliRunner()
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    policy_file = tmp_path / "bad_policy.yaml"
    policy_file.write_text("invalid_unknown_field: true\n")

    result = runner.invoke(
        cli, ["verify", "--artifact", str(art_file), "--policy", str(policy_file)]
    )
    assert result.exit_code == 2
    assert "Configuration Error" in result.output


def test_cli_verify_unexpected_system_error_returns_exit_3(tmp_path):
    """
    EXPLICIT DETERMINISTIC TEST SCENARIO FOR EXIT CODE 3:
    Simulates an unexpected storage/system error during verification execution
    and verifies that the CLI traps it and exits with ExitCode 3.
    """
    runner = CliRunner()
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    with patch(
        "provenanceguard.core.policy.risk_engine.RiskEngine.evaluate_risk",
        side_effect=RuntimeError("Controlled internal storage subsystem failure"),
    ):
        result = runner.invoke(cli, ["verify", "--artifact", str(art_file)])
        assert result.exit_code == 3
        assert "Unexpected System Failure" in result.output


def test_cli_inspect_command(tmp_path):
    runner = CliRunner()
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfakeheader")

    # Text mode
    res_text = runner.invoke(cli, ["inspect", "--artifact", str(art_file)])
    assert res_text.exit_code == 0
    assert "Inspecting artifact: app.bin" in res_text.output

    # JSON mode
    res_json = runner.invoke(cli, ["inspect", "--artifact", str(art_file), "--json-output"])
    assert res_json.exit_code == 0
    assert '"file_name": "app.bin"' in res_json.output


def test_cli_policy_validate_command(tmp_path):
    runner = CliRunner()

    valid_yaml = tmp_path / "valid.yaml"
    valid_yaml.write_text("name: my-policy\nwarning_threshold: 30\nblock_threshold: 70\n")

    invalid_yaml = tmp_path / "invalid.yaml"
    invalid_yaml.write_text("unknown_extra_field: true\n")

    # Valid policy -> exit 0
    res_valid = runner.invoke(cli, ["policy", "validate", "--policy", str(valid_yaml)])
    assert res_valid.exit_code == 0
    assert "VALID" in res_valid.output

    # Invalid policy -> exit 2
    res_invalid = runner.invoke(cli, ["policy", "validate", "--policy", str(invalid_yaml)])
    assert res_invalid.exit_code == 2
    assert "Policy Configuration Error" in res_invalid.output


def test_cli_provenance_verify_command(tmp_path):
    import json

    runner = CliRunner()

    att_file = tmp_path / "attestation.json"
    att_data = {
        "dsse_report": {
            "payload_type": "text/plain",
            "payload_sha256": "abc",
            "decoded_payload_size": 10,
            "signatures_observed": 1,
            "signatures_verified": 1,
            "key_ids_verified": ["k1"],
            "signature_verified": True,
        }
    }
    att_file.write_text(json.dumps(att_data))

    res_valid = runner.invoke(cli, ["provenance", "verify", "--attestation", str(att_file)])
    assert res_valid.exit_code == 0
    assert "Status: VALID" in res_valid.output

    # Failed attestation -> exit 1
    att_bad_file = tmp_path / "bad_attestation.json"
    att_bad_data = {
        "dsse_report": {
            "payload_type": "text/plain",
            "payload_sha256": "abc",
            "decoded_payload_size": 10,
            "signatures_observed": 1,
            "signatures_verified": 0,
            "key_ids_verified": [],
            "signature_verified": False,
        }
    }
    att_bad_file.write_text(json.dumps(att_bad_data))

    res_bad = runner.invoke(cli, ["provenance", "verify", "--attestation", str(att_bad_file)])
    assert res_bad.exit_code == 1
    assert "Verification Failures" in res_bad.output
