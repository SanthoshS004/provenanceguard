"""
Structured JSON Logger for ProvenanceGuard
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict


class JSONFormatter(logging.Formatter):
    """
    Formats log records into structured single-line JSON objects.
    Enforces automatic scrubbing of secret and credential fields.
    """

    REDACTED_KEYS = {
        "password",
        "token",
        "secret",
        "private_key",
        "authorization",
        "bearer",
        "api_key",
    }

    def format(self, record: logging.LogRecord) -> str:
        log_entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "service": getattr(record, "service", "provenanceguard"),
            "severity": record.levelname,
            "event": getattr(record, "event", record.getMessage()),
            "message": record.getMessage(),
        }

        # Add extra correlation IDs if present
        for field in ["trace_id", "request_id", "organization_id", "project_id", "verification_id"]:
            if hasattr(record, field):
                log_entry[field] = getattr(record, field)

        # Sanitize extra fields
        if hasattr(record, "extra_data") and isinstance(record.extra_data, dict):
            sanitized_extra = {}
            for k, v in record.extra_data.items():
                if any(red in k.lower() for red in self.REDACTED_KEYS):
                    sanitized_extra[k] = "[REDACTED]"
                else:
                    sanitized_extra[k] = v
            log_entry["extra"] = sanitized_extra

        return json.dumps(log_entry)


def get_logger(name: str = "provenanceguard") -> logging.Logger:
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
    return logger
