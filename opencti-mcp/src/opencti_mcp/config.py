# coding: utf-8
"""Configuration loader for the OpenCTI MCP server.

Reads connection settings from environment variables or a .env file.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass
class Config:
    """Runtime configuration derived from environment variables."""

    opencti_url: str
    opencti_token: str
    ssl_verify: bool | str
    log_level: str
    transport: str  # "stdio" | "sse"
    sse_host: str
    sse_port: int
    api_key: str  # empty string means no SSE authentication required
    allow_unauthenticated_sse: bool
    max_request_body_bytes: int
    max_concurrent_requests: int
    rate_limit_per_minute: int


def load_config() -> Config:
    """Load and validate configuration from the environment.

    Required environment variables:
        OPENCTI_URL   — base URL of the OpenCTI instance (e.g. ``http://localhost:4000``)
        OPENCTI_TOKEN — API bearer token

    Optional environment variables:
        OPENCTI_SSL_VERIFY  — ``"true"``/``"false"`` or path to CA bundle (default: ``"true"``)
        LOG_LEVEL           — Python log level name (default: ``"info"``)
        MCP_TRANSPORT       — ``"stdio"`` (default) or ``"sse"``
        MCP_SSE_HOST        — bind host for SSE transport (default: ``"127.0.0.1"``)
        MCP_SSE_PORT        — bind port for SSE transport (default: ``8000``)
        MCP_API_KEY         — bearer token required on every SSE request (default: unset/disabled)
        MCP_MAX_BODY_BYTES  — maximum SSE HTTP request body size (default: ``1048576``)
        MCP_MAX_CONCURRENT  — maximum concurrent SSE HTTP requests (default: ``20``)
        MCP_RATE_LIMIT_PER_MINUTE — maximum SSE HTTP requests per client/minute (default: ``60``)

    :raises ValueError: if a required variable is missing.
    :return: populated :class:`Config` instance.
    """
    opencti_url = os.getenv("OPENCTI_URL", "").strip()
    if not opencti_url:
        raise ValueError("OPENCTI_URL environment variable is required")

    opencti_token = os.getenv("OPENCTI_TOKEN", "").strip()
    if not opencti_token:
        raise ValueError("OPENCTI_TOKEN environment variable is required")

    # Preserve the original value for the CA-bundle path case; only lowercase
    # for the boolean comparison so that file-system paths are not corrupted.
    ssl_raw = os.getenv("OPENCTI_SSL_VERIFY", "true").strip()
    ssl_lower = ssl_raw.lower()
    if ssl_lower in ("false", "0", "no"):
        ssl_verify: bool | str = False
    elif ssl_lower in ("true", "1", "yes"):
        ssl_verify = True
    else:
        # Treat as a path to a CA bundle file — preserve original case
        ssl_verify = ssl_raw

    transport = os.getenv("MCP_TRANSPORT", "stdio").lower().strip()
    if transport not in {"stdio", "sse"}:
        raise ValueError("MCP_TRANSPORT must be either 'stdio' or 'sse'")

    sse_port_raw = os.getenv("MCP_SSE_PORT", "8000").strip()
    try:
        sse_port = int(sse_port_raw)
    except ValueError as exc:
        raise ValueError("MCP_SSE_PORT must be an integer") from exc
    if not (1 <= sse_port <= 65535):
        raise ValueError("MCP_SSE_PORT must be in range 1..65535")

    allow_unauthenticated_sse = os.getenv(
        "MCP_ALLOW_UNAUTHENTICATED_SSE", "false"
    ).strip().lower() in (
        "true",
        "1",
        "yes",
    )

    max_request_body_bytes = _positive_int_env("MCP_MAX_BODY_BYTES", 1_048_576)
    max_concurrent_requests = _positive_int_env("MCP_MAX_CONCURRENT", 20)
    rate_limit_per_minute = _positive_int_env("MCP_RATE_LIMIT_PER_MINUTE", 60)

    return Config(
        opencti_url=opencti_url,
        opencti_token=opencti_token,
        ssl_verify=ssl_verify,
        log_level=os.getenv("LOG_LEVEL", "info"),
        transport=transport,
        sse_host=os.getenv("MCP_SSE_HOST", "127.0.0.1"),
        sse_port=sse_port,
        api_key=os.getenv("MCP_API_KEY", ""),
        allow_unauthenticated_sse=allow_unauthenticated_sse,
        max_request_body_bytes=max_request_body_bytes,
        max_concurrent_requests=max_concurrent_requests,
        rate_limit_per_minute=rate_limit_per_minute,
    )


def _positive_int_env(name: str, default: int) -> int:
    raw_value = os.getenv(name, str(default)).strip()
    try:
        value = int(raw_value)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be greater than 0")
    return value
