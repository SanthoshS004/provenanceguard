"""
Integration Tests for Jenkins Pipeline Thin Adapter.
"""

from provenanceguard.integrations.jenkins.pipeline import JenkinsPipelineRunner


def test_jenkins_pipeline_runner_pass(tmp_path):
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    env = {"ARTIFACT_PATH": str(art_file)}
    runner = JenkinsPipelineRunner()
    exit_code = runner.run(env=env)
    assert exit_code == 0


def test_jenkins_pipeline_runner_block(tmp_path):
    art_file = tmp_path / "app.bin"
    art_file.write_bytes(b"\x7fELFfake")

    policy_file = tmp_path / "block_policy.yaml"
    policy_file.write_text("require_valid_signature: true\n")

    env = {
        "ARTIFACT_PATH": str(art_file),
        "POLICY_PATH": str(policy_file),
    }

    runner = JenkinsPipelineRunner()
    exit_code = runner.run(env=env)
    assert exit_code == 1


def test_jenkins_pipeline_runner_config_error(tmp_path):
    runner = JenkinsPipelineRunner()
    exit_code = runner.run(env={})
    assert exit_code == 2
