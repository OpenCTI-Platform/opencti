# coding: utf-8
"""Tests for MCP server transport helpers."""

from __future__ import annotations

from typing import Any

from starlette.responses import Response
from starlette.routing import Route
from starlette.types import Message

from opencti_mcp.config import Config
from opencti_mcp.server import _add_sse_request_controls


def _config(**overrides: Any) -> Config:
    values = {
        "opencti_url": "http://localhost:4000",
        "opencti_token": "token",
        "ssl_verify": True,
        "log_level": "info",
        "transport": "sse",
        "sse_host": "127.0.0.1",
        "sse_port": 8000,
        "api_key": "mcp-key",
        "allow_unauthenticated_sse": False,
        "max_request_body_bytes": 4,
        "max_concurrent_requests": 20,
        "rate_limit_per_minute": 60,
    }
    values.update(overrides)
    return Config(**values)


async def test_body_limit_rejects_chunked_request_without_content_length() -> None:
    from starlette.applications import Starlette

    called = False

    async def endpoint(request: Any) -> Response:
        nonlocal called
        called = True
        return Response("ok")

    app = Starlette(routes=[Route("/", endpoint, methods=["POST"])])
    _add_sse_request_controls(app, _config())

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "root_path": "",
    }
    messages: list[Message] = [
        {"type": "http.request", "body": b"123", "more_body": True},
        {"type": "http.request", "body": b"45", "more_body": False},
    ]
    sent: list[Message] = []

    async def receive() -> Message:
        return messages.pop(0)

    async def send(message: Message) -> None:
        sent.append(message)

    await app(scope, receive, send)

    assert called is False
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413
