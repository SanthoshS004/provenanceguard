"""
Unit tests for Image Config Env Normalization & Secret Redaction.
"""

import pytest

from provenanceguard.analyzers.oci.oci_adapters import OCIMalformedConfigError
from provenanceguard.core.verification.oci_compare import (
    normalize_env_dict,
    redact_secret_env_value,
)


def test_env_reorder_semantic_equality():
    env1 = ["PATH=/usr/bin", "FOO=bar", "BAZ=qux"]
    env2 = ["BAZ=qux", "PATH=/usr/bin", "FOO=bar"]

    d1 = normalize_env_dict(env1)
    d2 = normalize_env_dict(env2)
    assert d1 == d2


def test_env_duplicate_key_last_occurrence_wins():
    env = ["FOO=initial", "BAR=1", "FOO=overridden"]
    d = normalize_env_dict(env)
    assert d["FOO"] == "overridden"
    assert d["BAR"] == "1"


def test_env_malformed_entry_rejection():
    with pytest.raises(OCIMalformedConfigError):
        normalize_env_dict(["MALFORMED_ENV_NO_EQUALS"])


def test_env_empty_value_preservation():
    env = ["EMPTY_KEY="]
    d = normalize_env_dict(env)
    assert d["EMPTY_KEY"] == ""


def test_env_secret_redaction():
    assert redact_secret_env_value("API_SECRET_KEY", "super_secret_val") == "***REDACTED***"
    assert redact_secret_env_value("DATABASE_PASSWORD", "db_pass_123") == "***REDACTED***"
    assert redact_secret_env_value("NORMAL_PATH", "/usr/bin") == "/usr/bin"
