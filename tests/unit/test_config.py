"""
Unit Tests for Configuration Loader
"""

from pathlib import Path

import pytest

from provenanceguard.core.common.config import load_config


def test_load_development_config():
    config_path = Path("config/development.yaml")
    assert config_path.exists(), "development.yaml should exist"

    config = load_config(config_path)
    assert config["environment"] == "development"
    assert "server" in config
    assert "database" in config
    assert "security" in config


def test_load_nonexistent_config():
    with pytest.raises(FileNotFoundError):
        load_config(Path("config/nonexistent.yaml"))
