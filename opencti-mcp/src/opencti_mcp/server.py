# coding: utf-8
"""OpenCTI MCP server entrypoint.

Starts the Model Context Protocol server and registers all tools and resources.
Supports both ``stdio`` (for direct LLM tool use) and ``sse`` (HTTP/SSE for
remote deployment) transports, controlled by the ``MCP_TRANSPORT`` environment
variable.

Usage::

    # stdio (default, launched directly by an MCP client):
    OPENCTI_URL=http://localhost:4000 OPENCTI_TOKEN=<token> python -m opencti_mcp.server

    # SSE / HTTP (for remote deployment):
    MCP_TRANSPORT=sse MCP_SSE_HOST=0.0.0.0 MCP_SSE_PORT=8000 \\
        OPENCTI_URL=http://opencti:4000 OPENCTI_TOKEN=<token> \\
        python -m opencti_mcp.server

    # SSE with Bearer token authentication:
    MCP_TRANSPORT=sse MCP_API_KEY=<secret> ... python -m opencti_mcp.server
"""

from __future__ import annotations

import asyncio
import logging
import sys
from secrets import compare_digest
from time import monotonic
from typing import Any

from mcp.server.fastmcp import FastMCP

from opencti_mcp.client import init_client
from opencti_mcp.config import Config, load_config
from opencti_mcp.resources import stix_export
from opencti_mcp.tools import (
    cases,
    enrichment,
    indicators,
    investigations,
    observables,
    relationships,
    reports,
    search,
)

# ---------------------------------------------------------------------------
# Logging — write structured output to stderr so it does not pollute the
# MCP stdio protocol stream.
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("opencti_mcp")


def _add_sse_request_controls(app: Any, cfg: Config) -> None:
    """Add process-local request guards for the SSE HTTP app."""
    from starlette.middleware.base import BaseHTTPMiddleware
    from starlette.responses import Response

    class _BodySizeLimitMiddleware:
        def __init__(self, app: Any) -> None:
            self.app = app

        async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
            if scope["type"] != "http":
                await self.app(scope, receive, send)
                return

            messages = []
            body_size = 0
            more_body = True
            while more_body:
                message = await receive()
                messages.append(message)
                if message["type"] != "http.request":
                    continue
                body_size += len(message.get("body", b""))
                if body_size > cfg.max_request_body_bytes:
                    response = Response("Request body too large", status_code=413)
                    await response(scope, receive, send)
                    return
                more_body = message.get("more_body", False)

            async def replay_receive() -> Any:
                if messages:
                    return messages.pop(0)
                return {"type": "http.request", "body": b"", "more_body": False}

            await self.app(scope, replay_receive, send)

    semaphore = asyncio.Semaphore(cfg.max_concurrent_requests)
    request_windows: dict[str, list[float]] = {}

    class _RequestControlsMiddleware(BaseHTTPMiddleware):
        async def dispatch(self, request: Any, call_next: Any) -> Any:
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    body_size = int(content_length)
                except ValueError:
                    return Response("Invalid Content-Length", status_code=400)
                if body_size > cfg.max_request_body_bytes:
                    return Response("Request body too large", status_code=413)

            client_host = request.client.host if request.client else "unknown"
            now = monotonic()
            window_start = now - 60
            timestamps = [ts for ts in request_windows.get(client_host, []) if ts > window_start]
            if len(timestamps) >= cfg.rate_limit_per_minute:
                request_windows[client_host] = timestamps
                return Response("Rate limit exceeded", status_code=429)
            timestamps.append(now)
            request_windows[client_host] = timestamps

            if semaphore.locked():
                return Response("Too many concurrent requests", status_code=503)
            await semaphore.acquire()
            try:
                return await call_next(request)
            finally:
                semaphore.release()

    app.add_middleware(_RequestControlsMiddleware)
    app.add_middleware(_BodySizeLimitMiddleware)


def _run_sse(mcp: FastMCP, cfg: Config) -> None:
    """Start SSE transport, optionally with Bearer token authentication.

    When ``MCP_API_KEY`` is set every incoming SSE request must carry an
    ``Authorization: Bearer <key>`` header; requests without it are rejected
    with HTTP 401.

    Falls back to the built-in ``mcp.run`` runner only for explicitly
    unauthenticated development mode on older mcp library versions.
    """
    try:
        app = mcp.sse_app()
    except AttributeError:
        if cfg.api_key:
            raise RuntimeError(
                "MCP_API_KEY is set but cannot be enforced: mcp.sse_app() is unavailable"
            )
        if not cfg.allow_unauthenticated_sse:
            raise RuntimeError(
                "Refusing unauthenticated SSE: set MCP_API_KEY or MCP_ALLOW_UNAUTHENTICATED_SSE=true"
            )
        logger.warning(
            "Running unauthenticated SSE due to legacy mcp library and explicit override"
        )
        mcp.run(transport="sse")
        return

    _add_sse_request_controls(app, cfg)

    import uvicorn

    if cfg.api_key:
        from starlette.middleware.base import BaseHTTPMiddleware
        from starlette.responses import Response

        _key = cfg.api_key

        class _BearerAuthMiddleware(BaseHTTPMiddleware):
            async def dispatch(self, request: Any, call_next: Any) -> Any:
                auth = request.headers.get("Authorization", "")
                if not (auth.startswith("Bearer ") and compare_digest(auth[7:], _key)):
                    return Response(
                        content="Unauthorized",
                        status_code=401,
                        media_type="text/plain",
                    )
                return await call_next(request)

        app.add_middleware(_BearerAuthMiddleware)
        logger.info("SSE transport: Bearer token authentication enabled")
        uvicorn.run(app, host=cfg.sse_host, port=cfg.sse_port, log_level="warning")
    else:
        if not cfg.allow_unauthenticated_sse:
            raise RuntimeError(
                "Refusing unauthenticated SSE: set MCP_API_KEY or MCP_ALLOW_UNAUTHENTICATED_SSE=true"
            )
        logger.warning(
            "SSE transport: running unauthenticated because MCP_ALLOW_UNAUTHENTICATED_SSE=true"
        )
        uvicorn.run(app, host=cfg.sse_host, port=cfg.sse_port, log_level="warning")


def build_server() -> tuple[FastMCP, Config]:
    """Construct and configure the MCP server.

    Loads config, initialises the pycti client, and registers all tools and
    resources.  Returns the configured :class:`FastMCP` instance and the
    :class:`Config` so that the transport can be selected.

    :return: ``(mcp, cfg)`` tuple.
    :raises ValueError: if required environment variables are missing.
    """
    cfg = load_config()
    logger.setLevel(cfg.log_level.upper())
    logger.info("Initialising OpenCTI MCP server")

    init_client(cfg)

    mcp = FastMCP(
        "OpenCTI",
        instructions=(
            "You are connected to an OpenCTI threat-intelligence platform. "
            "Use the available tools to look up, create, and enrich indicators, "
            "observables, reports, cases (incident response, RFIs), and "
            "investigation workspaces.  All objects follow the STIX 2.1 standard."
        ),
    )

    # Register tools
    search.register(mcp)
    indicators.register(mcp)
    observables.register(mcp)
    reports.register(mcp)
    cases.register(mcp)
    investigations.register(mcp)
    enrichment.register(mcp)
    relationships.register(mcp)

    # Register resources (read-only context)
    stix_export.register(mcp)

    logger.info("OpenCTI MCP server ready")
    return mcp, cfg


def main() -> None:
    """Start the MCP server using the transport specified in the environment."""
    mcp, cfg = build_server()

    if cfg.transport == "sse":
        logger.info("Starting SSE transport on %s:%s", cfg.sse_host, cfg.sse_port)
        _run_sse(mcp, cfg)
    else:
        logger.info("Starting stdio transport")
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
