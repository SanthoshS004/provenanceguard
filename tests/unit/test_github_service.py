"""Unit tests for GitHubIntegrationService."""

import io
import os
import zipfile
import pytest
from unittest.mock import MagicMock, patch

from provenanceguard.integrations.github.service import (
    GitHubAuthenticationError,
    GitHubIntegrationError,
    GitHubIntegrationService,
    GitHubResourceNotFoundError,
)


def test_validate_credentials_missing_token():
    service = GitHubIntegrationService(token="")
    with pytest.raises(GitHubAuthenticationError) as exc_info:
        service.validate_credentials()
    assert "NO_GITHUB_TOKEN" in str(exc_info.value)


@patch("urllib.request.urlopen")
def test_validate_credentials_success(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"login": "testuser", "name": "Test User"}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    service = GitHubIntegrationService(token="ghp_test_token")
    res = service.validate_credentials()
    assert res["valid"] is True
    assert res["user"] == "testuser"


def test_get_repository_info_invalid_format():
    service = GitHubIntegrationService(token="ghp_test_token")
    with pytest.raises(ValueError):
        service.get_repository_info("invalid_repo_string")


@patch("urllib.request.urlopen")
def test_get_latest_commit_success(mock_urlopen):
    mock_resp = MagicMock()
    mock_resp.read.return_value = b'{"sha": "a1b2c3d4e5f67890", "commit": {"message": "Initial commit", "author": {"name": "Dev", "date": "2026-09-18T00:00:00Z"}}}'
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    service = GitHubIntegrationService(token="ghp_test")
    res = service.get_latest_commit("owner/repo", "main")
    assert res["sha"] == "a1b2c3d4e5f67890"
    assert res["short_sha"] == "a1b2c3d"
    assert res["message"] == "Initial commit"


def test_demo_collect_artifact():
    service = GitHubIntegrationService()
    content, filename, git_meta = service.demo_collect_artifact()
    assert len(content) > 0
    assert filename.endswith(".elf")
    assert git_meta["repository"] == "demo-org/provenanceguard-demo"
    assert git_meta["branch"] == "main"
    assert git_meta["commit_sha"] == "a1b2c3d4e5f67890123456789abcdef012345678"


def test_safe_zip_extraction_validation():
    service = GitHubIntegrationService(token="ghp_test")
    
    # Create valid in-memory zip
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as zf:
        zf.writestr("app-release.bin", b"\x7fELF\x02\x01\x01\x00BinaryContent")
    zip_bytes = zip_buffer.getvalue()

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.read.return_value = zip_bytes
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        extracted_bytes, filename = service.download_and_extract_artifact("owner/repo", "12345")
        assert extracted_bytes == b"\x7fELF\x02\x01\x01\x00BinaryContent"
        assert filename == "app-release.bin"
