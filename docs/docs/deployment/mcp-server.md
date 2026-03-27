# MCP Server

## Introduction

OpenCTI embeds a native [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that allows AI assistants and tools to interact with the platform programmatically. Any MCP-compatible client -- such as Claude Desktop, Cursor, Filigran Copilot, or any custom integration -- can connect directly to OpenCTI and perform threat intelligence operations through a standardized protocol.

The MCP server uses the **Streamable HTTP** transport (MCP specification 2025-03-26), exposing a single `POST {basePath}/mcp` endpoint that handles JSON-RPC 2.0 requests.

## Enabling MCP

### Platform-level toggle

MCP is controlled by a global platform setting. Administrators can enable or disable the MCP server from **Settings > Security > Policies**, in the **MCP Server** card.

When disabled at the platform level, MCP is completely unavailable for all users regardless of group or organization settings.

### Per-group and per-organization control

When MCP is enabled at the platform level, administrators can further restrict access per group or per organization:

- **Groups**: In **Settings > Security > Groups > [Group] > Edit**, toggle **"Allow MCP access for users in this group"**.
- **Organizations**: In **Settings > Security > Organizations > [Organization] > Edit**, toggle **"Allow MCP access for users in this organization"**.

Both settings default to **enabled** (allowed). The resolution logic follows an **OR** pattern:

- If a user belongs to **any** group or organization where MCP is allowed, MCP is enabled for that user.
- MCP is disabled for a user only if **all** their groups **and** all their organizations have MCP explicitly disabled.
- Users with no groups and no organizations inherit the platform-level setting directly.

The `mcp_allowed` status is visible in the group overview under the **Permissions** section.

## Authentication

The MCP endpoint reuses OpenCTI's existing authentication mechanisms:

- **Bearer token**: Pass an API token in the `Authorization: Bearer <token>` header.
- **API key**: Use the same tokens generated from the user profile page.

No additional authentication setup is required. The MCP server enforces the same permissions as the GraphQL API -- users can only access data they are authorized to see.

## Connecting an MCP client

### Endpoint URL

The MCP endpoint is available at:

```
POST https://<your-opencti-instance>{basePath}/mcp
```

For a default installation, this is typically `https://your-instance/mcp`.

### Client configuration

Most MCP clients accept a JSON configuration. The user profile page (**Profile > MCP access**) provides a ready-to-copy configuration snippet:

```json
{
  "mcpServers": {
    "opencti": {
      "url": "https://your-instance/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-token>"
      }
    }
  }
}
```

!!! tip "Profile page"
    
    The MCP access card on the user profile page is only visible when MCP is enabled for the current user (platform setting + group/organization permissions). It shows the exact endpoint URL and a copyable configuration snippet with the correct base URL.

### Claude Desktop

Add the following to your Claude Desktop MCP configuration file (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "opencti": {
      "url": "https://your-instance/mcp",
      "headers": {
        "Authorization": "Bearer <your-api-token>"
      }
    }
  }
}
```

### Cursor IDE

In Cursor settings, add a new MCP server with the URL and authentication header as shown above.

## Available tools

The MCP server exposes **24 tools** for STIX entity management, mirroring the capabilities of the Filigran Copilot OpenCTI integration:

### Search and read

| Tool | Description |
|------|-------------|
| `search_opencti` | Search entities by keyword with optional type filter |
| `get_opencti_entity` | Get full details of an entity by ID |
| `get_opencti_relationship` | Get full details of a relationship by ID |
| `list_opencti_entities` | List STIX domain objects with filters and ordering |
| `list_opencti_observables` | List cyber observables with filters |
| `list_opencti_relationships` | List relationships for an entity |
| `get_opencti_container_full` | Get a container with all contained entities |

### Create

| Tool | Description |
|------|-------------|
| `create_opencti_relationship` | Create a STIX core relationship |
| `create_opencti_observable` | Create a cyber observable (with optional indicator) |
| `create_opencti_note` | Create an analyst note on objects |
| `create_opencti_indicator` | Create an indicator from a STIX pattern or observable |
| `create_opencti_container` | Create a Report, Case, or Grouping |
| `create_opencti_entity` | Create a generic STIX domain object |

### Update

| Tool | Description |
|------|-------------|
| `update_opencti_field` | Update a field on a STIX domain object |
| `update_opencti_relationship_field` | Update a field on a relationship |

### Delete

| Tool | Description |
|------|-------------|
| `delete_opencti_entity` | Delete a STIX core object |
| `delete_opencti_relationship` | Delete a relationship |

### Labels and markings

| Tool | Description |
|------|-------------|
| `add_opencti_label` | Add a label to an entity |
| `remove_opencti_label` | Remove a label from an entity |
| `add_opencti_marking` | Add a marking definition to an entity |
| `remove_opencti_marking` | Remove a marking definition from an entity |

### Containers

| Tool | Description |
|------|-------------|
| `add_opencti_to_container` | Add objects to a container |
| `remove_opencti_from_container` | Remove objects from a container |

### Advanced

| Tool | Description |
|------|-------------|
| `promote_opencti_observable` | Promote an observable to an indicator |

## Technical details

### Protocol

- **Transport**: Streamable HTTP (MCP specification 2025-03-26)
- **Encoding**: JSON-RPC 2.0 over HTTP POST
- **Session mode**: Stateless (no session tracking)
- **SDK**: `@modelcontextprotocol/sdk` v1.27.1

### Internal execution

All tools execute GraphQL queries directly against the internal schema using `graphql()` from `graphql-js`. This means:

- **No HTTP overhead**: Tool calls do not make HTTP round-trips to the GraphQL endpoint.
- **Full permission enforcement**: The authenticated user's context flows through to all internal queries.
- **Same data access**: Tools have the same access as the user would have through the GraphQL API.

### Security

- **STIX pattern sanitization**: Values interpolated into STIX patterns are escaped to prevent injection.
- **Numeric validation**: Integer values (e.g., Autonomous System numbers) are validated before use.
- **Entity-type-aware aliases**: The correct alias field name (`aliases` vs `x_opencti_aliases`) is used per entity type.
- **Per-request context isolation**: Each MCP request runs in its own `AsyncLocalStorage` context to prevent cross-request data leaks under concurrency.

### Configuration

The MCP server is enabled by default. To disable it entirely via configuration (in addition to the UI toggle):

```yaml
app:
  mcp:
    enabled: false
```

## Limitations

- **File upload**: The `upload_opencti_file` and `import_opencti_dashboard` operations are not available through MCP because they require multipart form data. Use the REST API or UI for file operations.
- **Streaming**: The MCP server operates in stateless mode. Server-to-client notifications and streaming responses are not supported.
- **Rate limiting**: There is currently no built-in rate limiting on the MCP endpoint. Consider using a reverse proxy for rate limiting in production environments.
