# syntax=docker/dockerfile:1
# Build the OpenCTI MCP server image.
#
# Usage:
#   docker build -t opencti-mcp .
#   docker run --rm \
#     -e OPENCTI_URL=http://opencti:4000 \
#     -e OPENCTI_TOKEN=<token> \
#     -e MCP_TRANSPORT=sse \
#     -e MCP_SSE_HOST=0.0.0.0 \
#     -e MCP_SSE_PORT=8000 \
#     -e MCP_API_KEY=<mcp-bearer-token> \
#     -p 8000:8000 \
#     opencti-mcp

FROM python:3.12.7-slim

WORKDIR /app

# Copy package metadata first for better layer caching
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package (no dev extras needed at runtime)
RUN pip install --no-cache-dir .

# Run as non-root for security
RUN useradd --no-create-home --shell /bin/false mcp
USER mcp

ENV MCP_TRANSPORT=sse \
    MCP_SSE_HOST=0.0.0.0 \
    MCP_SSE_PORT=8000

EXPOSE 8000

# Health check: open an HTTP connection to the SSE endpoint. 200 means the
# endpoint accepted the request, and 401 means the authenticated endpoint is
# up but the health check did not send a bearer token.
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "\
import http.client, sys; \
try: \
    c = http.client.HTTPConnection('localhost', 8000, timeout=5); \
    c.request('GET', '/sse'); \
    sys.exit(0 if c.getresponse().status in (200, 401) else 1); \
except Exception: \
    sys.exit(1)"

CMD ["opencti-mcp"]
