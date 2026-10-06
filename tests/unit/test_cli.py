"""
Unit Tests for CLI Application & Exit Codes
"""

from click.testing import CliRunner

from provenanceguard.apps.cli.exit_codes import ExitCode
from provenanceguard.apps.cli.main import cli


def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "provenanceguard" in result.output


def test_cli_verify_missing_artifact():
    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--artifact", "nonexistent.bin"])
    assert result.exit_code == 2  # Click parameter error exit code


def test_cli_verify_valid_file(tmp_path):
    artifact_file = tmp_path / "app.bin"
    artifact_file.write_text("test binary content")

    runner = CliRunner()
    result = runner.invoke(cli, ["verify", "--artifact", str(artifact_file)])
    assert result.exit_code == ExitCode.PASS
