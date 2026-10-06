"""
CLI Smoke Tests Execution Script for Phase 9 Final Verification.
Runs actual CLI commands via Click CliRunner and subprocess CLI, recording exact commands and exit codes.
"""

import json
import os
import sys
from pathlib import Path
from click.testing import CliRunner

from provenanceguard.apps.cli.main import cli

def run_smoke_tests():
    runner = CliRunner()
    fixtures_dir = Path("scratch/cli_fixtures")
    fixtures_dir.mkdir(parents=True, exist_ok=True)

    # Fixture Files
    art_file = fixtures_dir / "app.bin"
    art_file.write_bytes(b"\x7fELF\x02\x01\x01\x00" + b"A" * 100)

    valid_policy = fixtures_dir / "valid_policy.yaml"
    valid_policy.write_text("name: valid-policy\nwarning_threshold: 50\nblock_threshold: 80\n")

    malformed_yaml = fixtures_dir / "malformed_yaml.yaml"
    malformed_yaml.write_text("name: bad:\n  - [invalid yaml {")

    invalid_schema = fixtures_dir / "invalid_schema.yaml"
    invalid_schema.write_text("unknown_extra_field: true\n")

    block_policy = fixtures_dir / "block_policy.yaml"
    block_policy.write_text("require_valid_signature: true\n")

    warning_policy = fixtures_dir / "warning_policy.yaml"
    warning_policy.write_text("warning_threshold: 10\nblock_threshold: 90\n")

    valid_attestation = fixtures_dir / "valid_attestation.json"
    valid_att_data = {
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
    valid_attestation.write_text(json.dumps(valid_att_data))

    invalid_attestation = fixtures_dir / "invalid_attestation.json"
    invalid_att_data = {
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
    invalid_attestation.write_text(json.dumps(invalid_att_data))

    results = []

    # A. policy validate
    # A1. Valid policy -> exit 0
    cmd_a1 = ["policy", "validate", "--policy", str(valid_policy)]
    res_a1 = runner.invoke(cli, cmd_a1)
    results.append(("A1: policy validate (valid)", " ".join(cmd_a1), res_a1.exit_code, 0))

    # A2. Malformed YAML -> exit 2
    cmd_a2 = ["policy", "validate", "--policy", str(malformed_yaml)]
    res_a2 = runner.invoke(cli, cmd_a2)
    results.append(("A2: policy validate (malformed YAML)", " ".join(cmd_a2), res_a2.exit_code, 2))

    # A3. Invalid schema -> exit 2
    cmd_a3 = ["policy", "validate", "--policy", str(invalid_schema)]
    res_a3 = runner.invoke(cli, cmd_a3)
    results.append(("A3: policy validate (invalid schema)", " ".join(cmd_a3), res_a3.exit_code, 2))

    # B. inspect
    # B1. Valid supported artifact -> exit 0
    cmd_b1 = ["inspect", "--artifact", str(art_file)]
    res_b1 = runner.invoke(cli, cmd_b1)
    results.append(("B1: inspect (valid artifact)", " ".join(cmd_b1), res_b1.exit_code, 0))

    # B2. Nonexistent artifact -> exit 2
    cmd_b2 = ["inspect", "--artifact", str(fixtures_dir / "nonexistent.bin")]
    res_b2 = runner.invoke(cli, cmd_b2)
    results.append(("B2: inspect (nonexistent artifact)", " ".join(cmd_b2), res_b2.exit_code, 2))

    # C. provenance verify
    # C1. Valid attestation -> exit 0
    cmd_c1 = ["provenance", "verify", "--attestation", str(valid_attestation)]
    res_c1 = runner.invoke(cli, cmd_c1)
    results.append(("C1: provenance verify (valid)", " ".join(cmd_c1), res_c1.exit_code, 0))

    # C2. Failed attestation -> exit 1
    cmd_c2 = ["provenance", "verify", "--attestation", str(invalid_attestation)]
    res_c2 = runner.invoke(cli, cmd_c2)
    results.append(("C2: provenance verify (failed attestation)", " ".join(cmd_c2), res_c2.exit_code, 1))

    # C3. Malformed attestation file -> exit 2
    cmd_c3 = ["provenance", "verify", "--attestation", str(fixtures_dir / "nonexistent.json")]
    res_c3 = runner.invoke(cli, cmd_c3)
    results.append(("C3: provenance verify (missing attestation)", " ".join(cmd_c3), res_c3.exit_code, 2))

    # D. verify
    # D1. PASS fixture -> exit 0
    cmd_d1 = ["verify", "--artifact", str(art_file), "--attestation", str(valid_attestation), "--policy", str(valid_policy)]
    res_d1 = runner.invoke(cli, cmd_d1)
    results.append(("D1: verify (PASS)", " ".join(cmd_d1), res_d1.exit_code, 0))

    # D2. PASS_WITH_WARNING fixture -> exit 0
    cmd_d2 = ["verify", "--artifact", str(art_file), "--policy", str(warning_policy)]
    res_d2 = runner.invoke(cli, cmd_d2)
    results.append(("D2: verify (PASS_WITH_WARNING)", " ".join(cmd_d2), res_d2.exit_code, 0))

    # D3. BLOCK fixture -> exit 1
    cmd_d3 = ["verify", "--artifact", str(art_file), "--policy", str(block_policy)]
    res_d3 = runner.invoke(cli, cmd_d3)
    results.append(("D3: verify (BLOCK)", " ".join(cmd_d3), res_d3.exit_code, 1))

    # D4. Configuration/Input Error -> exit 2
    cmd_d4 = ["verify", "--artifact", str(art_file), "--policy", str(invalid_schema)]
    res_d4 = runner.invoke(cli, cmd_d4)
    results.append(("D4: verify (CONFIG_ERROR)", " ".join(cmd_d4), res_d4.exit_code, 2))

    # D5. Unexpected System Error -> exit 3
    from unittest.mock import patch
    with patch("provenanceguard.core.policy.risk_engine.RiskEngine.evaluate_risk", side_effect=RuntimeError("Controlled storage error")):
        cmd_d5 = ["verify", "--artifact", str(art_file)]
        res_d5 = runner.invoke(cli, cmd_d5)
        results.append(("D5: verify (SYSTEM_ERROR)", " ".join(cmd_d5), res_d5.exit_code, 3))

    print("=== CLI SMOKE TEST RESULTS ===")
    all_matched = True
    for label, cmd, actual, expected in results:
        status = "MATCH" if actual == expected else "MISMATCH"
        if actual != expected:
            all_matched = False
        print(f"[{status}] {label}\n  Command: provenanceguard {cmd}\n  Actual Exit Code: {actual} | Expected Exit Code: {expected}\n")

    if not all_matched:
        sys.exit(1)

if __name__ == "__main__":
    run_smoke_tests()
