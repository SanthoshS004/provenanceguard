"""
Integration Tests for GitHub Actions Adapter.
"""

from provenanceguard.integrations.github.action import (
    GitHubActionRunner,
    sanitize_github_command_value,
)


def test_github_action_command_injection_sanitization():
    raw_text = "Evil Title\r\n::error::Injected Workflow Command\n%0A%0D"
    sanitized = sanitize_github_command_value(raw_text)
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert "::" not in sanitized
    assert "%0A" not in sanitized
    assert "%0D" not in sanitized
    assert sanitized == "Evil Title  --error--Injected Workflow Command"


def test_github_action_runner_missing_artifact_exit_2():
    runner = GitHubActionRunner()
    exit_code = runner.run(env={})
    assert exit_code == 2


def test_github_action_runner_valid_artifact_pass_exit_0(tmp_path):
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    summary_file = tmp_path / "summary.md"

    env = {
        "INPUT_ARTIFACT": str(art_file),
        "GITHUB_STEP_SUMMARY": str(summary_file),
    }

    runner = GitHubActionRunner()
    exit_code = runner.run(env=env)
    assert exit_code == 0
    assert summary_file.exists()
    summary_content = summary_file.read_text(encoding="utf-8")
    assert "ProvenanceGuard Verification Summary" in summary_content


def test_github_action_runner_block_policy_exit_1(tmp_path):
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    policy_file = tmp_path / "block_policy.yaml"
    policy_file.write_text("require_valid_signature: true\n")

    env = {
        "INPUT_ARTIFACT": str(art_file),
        "INPUT_POLICY": str(policy_file),
    }

    runner = GitHubActionRunner()
    exit_code = runner.run(env=env)
    assert exit_code == 1
