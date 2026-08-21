---
name: graphseq
description: Generate or update Graphseq architecture diagrams from repository context. Use when the user asks for a Graphseq / Graphit diagram, system architecture picture, isometric graph, or to update a .graphseq.json file.
---

# Graphseq diagrams

Emit **SemanticGraphInput** (no positions, sizes, ports, or routes). Compile it with the Graphseq MCP (`npx -y @graphseq/mcp`). Do not call an image model and do not invent coordinates.

## Loop

1. Read the relevant source, docs, and config. Do not invent services that are not in context.
2. Call `get_conventions` (or read `graphseq://prompt-context`).
3. Write `SemanticGraphInput` JSON.
4. Call `materialize`. If `{ ok: false, errors }`, fix and retry.
5. If cloud tools are configured, call `create_cloud_file` with a title and the materialized `document`, then give the user `editorUrl`.
6. Otherwise write the `document` to a `.graphseq.json` file, or `export_diagram` (`mermaid`) for a chat preview.

To edit an existing cloud diagram: `get_cloud_file` → `to_semantic` → change only what was asked → `materialize_edit` → `update_cloud_file`. Preserve ids.

## SemanticGraphInput rules

- Call `get_conventions` with `packs` before emitting a graph. Default without `packs` is **core + tech** only — not the full catalog.
- Foundation: `["core","tech"]`, `["core","systems"]`. Domain examples: `["core","argument"]`, `["core","org","decision"]`, `["core","physics"]`. Cloud: `["core","tech","aws"]` (prefer `aws-*` / `gcp-*` / `azure-*` ids over generic `service`/`database`).
- Node `type` must be a catalog id from the enabled packs. Use `list_node_types` with the same `packs` for the id list. Systems type `cloud` is a generic sink/source; vendor packs use prefixed ids (`aws-lambda`, …).
- Edges are `{ from: nodeId, to: nodeId }`. Zones (boundary role: `container`, `vpc`, `org-boundary`, `aws-vpc`, …) and `text` cannot be endpoints.
- Always set `layer` on content nodes: `0` source/gateway, `1` entity/process/channel, `2` store.
- Set `group` to a sibling zone node id so the zone wraps those members.
- Node `label` is a short title (~5 words). Sentences, quotes, and stats go in `description`.
- One edge per node pair. Collapse verbs onto one short 1–3 word label.
- Root stays under ~12 edges and ~14 content nodes. Split with `childDiagramId`.
- Non-trivial graphs: add a short presentation (3–6 steps). If more than ~8 labeled edges, set `edgeLabelsHidden: true`.

```json
{
  "rootDiagramId": "root",
  "diagrams": [
    {
      "id": "root",
      "name": "API + Database",
      "nodes": [
        { "id": "zone", "type": "container", "label": "App Zone" },
        { "id": "client", "type": "client", "label": "Browser", "layer": 0 },
        { "id": "api", "type": "service", "label": "API", "layer": 1, "group": "zone" },
        { "id": "db", "type": "database", "label": "Postgres", "layer": 2, "group": "zone" }
      ],
      "edges": [
        { "from": "client", "to": "api", "label": "HTTPS" },
        { "from": "api", "to": "db", "label": "SQL" }
      ]
    }
  ],
  "presentations": []
}
```
