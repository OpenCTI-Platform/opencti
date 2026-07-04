# OpenCTI MCP Server

The OpenCTI MCP server exposes OpenCTI threat-intelligence operations through
the Model Context Protocol (MCP). It uses the official `pycti` client to call
the OpenCTI GraphQL API.

## Features

| Category | Tools |
| --- | --- |
| Indicators | `lookup_indicator`, `list_indicators`, `get_indicator`, `add_indicator`, `update_indicator`, `promote_observable_to_indicator`, `get_indicator_relationships` |
| Observables | `lookup_observable`, `list_observables`, `get_observable`, `add_observable`, `enrich_observable`, `get_observable_indicators`, `get_observable_relationships` |
| Reports | `lookup_report`, `list_reports`, `create_report`, `add_object_to_report`, `get_report_objects`, `export_report_stix` |
| Cases | `create_incident_case`, `create_rfi`, `lookup_case`, `list_cases`, `add_object_to_case`, `update_case_status` |
| Tasks | `create_task`, `complete_task` |
| Investigations | `create_investigation`, `get_investigation`, `list_investigations`, `add_to_investigation`, `export_investigation_as_report`, `start_investigation_from_container` |
| Enrichment | `list_enrichment_connectors`, `enrich_entity`, `get_enrichment_status`, `get_entity_connectors` |
| Relationships | `create_relationship`, `lookup_relationships`, `create_sighting` |
| Search | `global_search`, `find_by_stix_id`, `find_by_external_reference` |

## Resources

| URI template | Description |
| --- | --- |
| `opencti://indicator/{id}` | Indicator details |
| `opencti://observable/{id}` | Observable details with related indicators |
| `opencti://report/{id}` | Report details with contained objects |
| `opencti://case/{id}` | Incident, RFI, or RFT case details |
| `opencti://investigation/{id}` | Investigation exported as a STIX 2.1 bundle |

## Requirements

- Python 3.10 or later
- A running OpenCTI instance
- An OpenCTI API token with the permissions required by the tools you enable

## Installation

From the repository root:

```bash
pip install -e ./opencti-mcp
```

For development:

```bash
cd opencti-mcp
pip install -r requirements.txt
pip install -r test-requirements.txt
pip install -e ".[dev]"
```

## Configuration

The server reads configuration from environment variables. A `.env` file in the
working directory is also supported.

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `OPENCTI_URL` | Yes |  | Base URL of the OpenCTI instance, for example `http://localhost:4000` |
| `OPENCTI_TOKEN` | Yes |  | OpenCTI API bearer token |
| `OPENCTI_SSL_VERIFY` | No | `true` | `true`, `false`, or a CA bundle path |
| `LOG_LEVEL` | No | `info` | Python log level |
| `MCP_TRANSPORT` | No | `stdio` | `stdio` or `sse` |
| `MCP_SSE_HOST` | No | `127.0.0.1` | Bind host for SSE transport |
| `MCP_SSE_PORT` | No | `8000` | Bind port for SSE transport |
| `MCP_API_KEY` | Required for SSE unless explicitly disabled |  | Bearer token required for SSE HTTP requests |
| `MCP_ALLOW_UNAUTHENTICATED_SSE` | No | `false` | Development-only opt-in for unauthenticated SSE |
| `MCP_MAX_BODY_BYTES` | No | `1048576` | Maximum SSE HTTP request body size |
| `MCP_MAX_CONCURRENT` | No | `20` | Maximum concurrent SSE HTTP requests |
| `MCP_RATE_LIMIT_PER_MINUTE` | No | `60` | Maximum SSE HTTP requests per client per minute |

## Usage

### stdio transport

Use `stdio` when an MCP client launches the server process directly:

```bash
OPENCTI_URL=http://localhost:4000 \
OPENCTI_TOKEN=<opencti-token> \
opencti-mcp
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "opencti": {
      "command": "opencti-mcp",
      "env": {
        "OPENCTI_URL": "http://localhost:4000",
        "OPENCTI_TOKEN": "<opencti-token>"
      }
    }
  }
}
```

### SSE transport

Use `sse` when exposing the server as an HTTP endpoint. SSE requires
`MCP_API_KEY` by default.

```bash
MCP_TRANSPORT=sse \
MCP_SSE_HOST=127.0.0.1 \
MCP_SSE_PORT=8000 \
MCP_API_KEY=<mcp-bearer-token> \
OPENCTI_URL=http://localhost:4000 \
OPENCTI_TOKEN=<opencti-token> \
opencti-mcp
```

Configure MCP clients to use:

```text
http://localhost:8000/sse
```

Clients must send:

```text
Authorization: Bearer <mcp-bearer-token>
```

## Docker

Build the MCP server image from `opencti-mcp/`:

```bash
cd opencti-mcp
docker build -t opencti-mcp .
```

Run it against an existing OpenCTI instance:

```bash
docker run --rm \
  -e OPENCTI_URL=http://opencti:4000 \
  -e OPENCTI_TOKEN=<opencti-token> \
  -e MCP_TRANSPORT=sse \
  -e MCP_SSE_HOST=0.0.0.0 \
  -e MCP_SSE_PORT=8000 \
  -e MCP_API_KEY=<mcp-bearer-token> \
  -p 8000:8000 \
  opencti-mcp
```

## Docker Compose

The `docker-compose.yml` in this directory starts OpenCTI and the MCP server
for local testing.

```bash
cd opencti-mcp
cp .env.example .env
```

Edit `.env` and set:

- `OPENCTI_ADMIN_TOKEN` to a UUID v4 value
- `MCP_API_KEY` to a random bearer token for MCP clients

Elasticsearch requires a higher virtual-memory limit on Linux and WSL2:

```bash
sudo sysctl -w vm.max_map_count=262144
```

Start the stack:

```bash
docker compose up -d
```

Default endpoints:

| Service | URL |
| --- | --- |
| OpenCTI UI | `http://localhost:4000` |
| MCP SSE endpoint | `http://localhost:8000/sse` |
| RabbitMQ management | `http://localhost:15672` |

Stop and remove local volumes:

```bash
docker compose down -v
```

## Development

```bash
cd opencti-mcp
pip install -r requirements.txt
pip install -r test-requirements.txt
pip install -e ".[dev]"
```

Run checks:

```bash
pytest tests/ -v
black --check src/ tests/
isort --check-only src/ tests/
flake8 src/ tests/ --ignore E,W
mypy src/
```

## Security

- Use a dedicated OpenCTI API token with least-privilege permissions.
- Do not expose SSE without `MCP_API_KEY` unless running an isolated local
  development environment.
- Bind SSE to `127.0.0.1` unless a reverse proxy provides TLS, authentication,
  request limits, and access controls.
- Keep `OPENCTI_SSL_VERIFY=true` in production. Use a CA bundle path for
  private certificate authorities.
- Tool and resource handlers return sanitized errors to MCP clients and log
  detailed exceptions server-side.
- The SSE app enforces process-local request body, rate, and concurrency
  limits. These controls are not a replacement for reverse-proxy limits in
  shared or internet-facing deployments.

## Architecture

```text
MCP client
    |
    | MCP protocol (stdio or SSE)
    v
opencti_mcp.server
    |
    | registers tools and resources
    v
opencti_mcp.tools / opencti_mcp.resources
    |
    | pycti
    v
OpenCTI GraphQL API
```

The server is designed for a single OpenCTI tenant per process. The pycti
client is initialized once at startup and shared by tool and resource handlers.
Run separate server processes for separate OpenCTI tenants.
