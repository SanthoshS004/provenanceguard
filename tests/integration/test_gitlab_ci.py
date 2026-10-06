"""
Integration Tests for GitLab CI Adapter & Code Quality JSON Schema Validation.
"""

import json

from provenanceguard.integrations.gitlab.ci import GitLabCIRunner


def test_gitlab_code_quality_schema_validation(tmp_path):
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    policy_file = tmp_path / "block_policy.yaml"
    policy_file.write_text("require_valid_signature: true\n")

    report_file = tmp_path / "gl-code-quality-report.json"

    env = {
        "ARTIFACT_PATH": str(art_file),
        "POLICY_PATH": str(policy_file),
        "GL_CODE_QUALITY_REPORT": str(report_file),
    }

    runner = GitLabCIRunner()
    exit_code = runner.run(env=env)

    # Policy requires valid signature -> BLOCK -> exit 1
    assert exit_code == 1
    assert report_file.exists()

    with open(report_file, "r", encoding="utf-8") as f:
        cq_data = json.load(f)

    assert isinstance(cq_data, list)
    assert len(cq_data) >= 1

    item = cq_data[0]
    assert "description" in item
    assert "check_name" in item
    assert "fingerprint" in item
    assert "severity" in item
    assert "location" in item
    assert item["severity"] in ("critical", "major", "minor", "info")
    assert item["location"]["path"] == str(art_file)
    assert "lines" in item["location"]
