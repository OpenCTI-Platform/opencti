# MCP server

## Introduction

OpenCTI can be used from any client compatible with the [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) — Cursor, Claude Desktop, Claude Code, or custom AI agents — through the native MCP server embedded in [XTM One](https://docs.xtmone.io/).

When an OpenCTI instance is registered with XTM One, XTM One automatically exposes an MCP server for it. AI clients connect to XTM One and work with the threat intelligence knowledge stored in OpenCTI: searching entities, reading and creating STIX objects, managing indicators, containers, labels and markings.

!!! note "Community feature"

    The OpenCTI MCP server is available in the Community Edition of XTM One. There is nothing to install on the OpenCTI side: the server activates as soon as the platform is registered with XTM One.

## Architecture

```
MCP client (Cursor, Claude Desktop, ...)
        |  Streamable HTTP (JSON-RPC 2.0)
        |  Authorization: Bearer <XTM One API key>
        v
XTM One   POST /mcp/opencti
        |  short-lived per-user token (verified via JWKS)
        v
OpenCTI   GraphQL API (acting as the calling user)
```

- The MCP endpoint is served by XTM One at `https://<your-xtm-one>/mcp/opencti` using the MCP Streamable HTTP transport.
- Clients authenticate with a personal XTM One API key (`fcp-...`) or an OAuth 2.1 access token.
- For every tool call, XTM One signs a short-lived token for the calling user (matched by email in OpenCTI), so all operations run with that user's permissions, data markings, and audit trail. The OpenCTI API token is never stored in or proxied through XTM One.

## Prerequisites

1. A running XTM One instance.
2. The OpenCTI platform registered with XTM One (the same registration that powers the embedded AI experience).
3. A user account existing on both platforms with the same email address.
4. A personal API key created in XTM One (`My Profile > API Keys`).

## Capabilities

The MCP server exposes the business and knowledge tool surface of OpenCTI:

| Category | Examples |
| -------- | -------- |
| Search & read | keyword search, entity / relationship / observable listing, container contents, entity statistics, top related entities, modification history |
| Create | STIX domain objects, observables, indicators, relationships, containers (reports, cases, groupings), notes |
| Update & delete | field updates on entities and relationships, entity and relationship deletion |
| Labels & markings | add / remove labels (auto-created when needed), add / remove TLP and other markings |
| Containers | add / remove objects in reports, cases, and groupings |
| Advanced | promote an observable to an indicator |

Platform administration is deliberately out of scope: no user, group, role, playbook, dashboard, notification, ingestion, data sharing or connector management is available through the MCP server. Knowledge changes are applied directly to the live knowledge graph with the calling user's permissions.

## Client configuration

In XTM One, open `My Profile > MCP Endpoint` to find the endpoint URL, the live connection status, and a ready-to-copy configuration. The configuration for Cursor (`.cursor/mcp.json`) or Claude Desktop (`claude_desktop_config.json`) looks like this:

```json
{
  "mcpServers": {
    "opencti": {
      "url": "https://<your-xtm-one>/mcp/opencti",
      "headers": {
        "Authorization": "Bearer fcp-..."
      }
    }
  }
}
```

You can verify the connection from a terminal:

```bash
curl -s -X POST https://<your-xtm-one>/mcp/opencti \
  -H "Authorization: Bearer fcp-..." \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}'
```

## Administration

Administrators can disable the MCP servers globally in XTM One under `Settings > MCP Endpoint` (Platform MCP Servers toggle). When disabled, the endpoint returns `403` for all clients.

| Response | Meaning |
| -------- | ------- |
| `401` | Missing or invalid API key / token |
| `403` | The platform MCP servers are disabled in XTM One settings |
| `404` | No OpenCTI platform is registered with XTM One |

!!! note "Full documentation"

    For more details about MCP endpoints, API keys and platform administration, please refer to the [XTM One documentation](https://docs.xtmone.io/).
