"""
Unit Tests for Structured JSON Logging & Secret Scrubbing
"""

import json
import logging

from provenanceguard.core.common.logging import JSONFormatter


def test_json_formatter_structure():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Test log event",
        args=(),
        exc_info=None,
    )

    formatted_str = formatter.format(record)
    data = json.loads(formatted_str)

    assert data["severity"] == "INFO"
    assert data["message"] == "Test log event"
    assert "timestamp" in data


def test_json_formatter_secret_scrubbing():
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Sensitive event",
        args=(),
        exc_info=None,
    )
    record.extra_data = {
        "user_id": "usr_123",
        "api_key": "secret_key_99999",
        "password": "super_secret_pass",
    }

    formatted_str = formatter.format(record)
    data = json.loads(formatted_str)

    assert data["extra"]["user_id"] == "usr_123"
    assert data["extra"]["api_key"] == "[REDACTED]"
    assert data["extra"]["password"] == "[REDACTED]"
