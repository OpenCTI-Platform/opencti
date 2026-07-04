# coding: utf-8
"""Error handling helpers for MCP tool/resource responses."""

from __future__ import annotations

import json
import logging


def safe_error_response(logger: logging.Logger, operation: str, exc: Exception) -> str:
    """Return a sanitized error payload and log full exception server-side."""
    logger.exception("%s failed", operation, exc_info=exc)
    return json.dumps(
        {
            "error": {
                "code": "internal_error",
                "message": "Request failed. Check server logs for details.",
                "operation": operation,
            }
        }
    )
