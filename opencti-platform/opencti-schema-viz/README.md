# OpenCTI Schema Viz

An explorer for the OpenCTI data model: entity and relationship types, their attributes, the relations allowed between them, and the type hierarchy.

## Using it

- **Canvas**: compact type cards. Click one to open its details; double-click (or the `+ n` badge) to expand its relations. Relations with many counterparts fold into a target group whose entries can be added one by one.
- **Inspector** (right): attributes grouped by the type that declares them, outgoing and incoming relations (including those inherited from an ancestor), subtypes and lineage. Every type name is a link.
- **Sidebar** (left): categories act as a clickable legend (unchecked = hidden from the canvas) and list their types; saved views restore a whole canvas. Built-in views ship with the app, your own are kept in the browser.
- **Search**: `⌘K` / `Ctrl K` or `/` searches types and attribute names (`x_mitre_id` → the types declaring it). `⇧↵` opens a type with its relations expanded.
- **Find path**: shortest chain of relations between two types, optionally following relation direction or ref attributes.
- **Navigation**: the breadcrumb keeps the visited types (`Alt ←` goes back), `Esc` closes the inspector, and `#type=Malware` in the URL links to a type.

Generic relations (`related-to`, `derived-from`, `duplicate-of`) and self-references are only drawn when a type is expanded, not when the canvas connects the visible types, otherwise they would link almost everything.

## Prerequisites

-   **Node.js** (v20+ recommended)
-   **Yarn**
-   **OpenCTI Source Code**: This project relies on the core OpenCTI backend to generate the schema. It expects `opencti-graphql` to be located at `../../opencti-graphql` relative to this project's script directory.

## Installation

Install the dependencies:

```bash
yarn install
```

## Schema Generation

The visualization is powered by a JSON file (`public/schema.json`) generated directly from the OpenCTI backend source code.

To generate or update the schema:

```bash
yarn generate
```

This command executes `scripts/generate-graph.ts`, which:
1.  Temporarily switches context to the `opencti-graphql` backend directory.
2.  Loads all Entity and Relationship type definitions.
3.  Validates attributes against official STIX 2.1 JSON schemas (automatically downloaded if missing).
4.  Exports the processed graph data to `public/schema.json`.

**Note**: If you change the backend schema (e.g., adding a new Entity or Attribute in `opencti-graphql`), you must run `yarn generate` again to see the changes here.

## Running Locally

Start the Vite development server:

```bash
yarn dev
```

Open [http://localhost:5173/opencti-schema/](http://localhost:5173/opencti-schema/) (the `base` set in `vite.config.ts`).

## Tests

```bash
yarn test
```

## Architecture

```txt
src/
├── app/            Shell: layout grid, top bar, schema loading, URL hash sync
├── data/           schema.json format, loader, normalization (lookup maps and adjacency, built once)
├── state/          Zustand stores: canvas and navigation, user saved views (persisted), built-in views
├── features/
│   ├── schema-graph/   buildVisibleGraph (pure: scope → nodes and edges), layout (Dagre behind a LayoutEngine
│   │                   interface, plus leaf packing), React Flow nodes, edges and canvas
│   ├── node-inspector/ Right panel
│   ├── filters/        Left panel and category legend
│   ├── saved-views/
│   ├── search/         Ranking, ⌘K palette, type combobox
│   ├── find-path/      Breadth-first search over relations
│   └── breadcrumb/
└── shared/         Token aliases for the canvas, type colours and icons, small compositions of library parts
```

Components subscribe to the exact store field they read (for instance, a node only re-renders when its own selection or expansion changes). The canvas re-layouts only when the set of visible nodes and edges changes, never on selection.

## Design system

The UI is built with [`@filigran/design-system`](https://www.npmjs.com/package/@filigran/design-system), pinned to the
version `opencti-front` uses, with no MUI. Its consumer rules ship in
`node_modules/@filigran/design-system/skills/consumer/` and apply here.

- `src/main.tsx` loads the fonts (Geologica, IBM Plex Sans and Mono) and the library's `dist/index.css`.
- The theme is the library's `.dark` / `.light` class on `<html>`, dark by default.
- Every colour, spacing, radius and typography value comes from a library token. `src/shared/theme/appTokens.css`
  only names the roles the canvas needs (`--sv-edge-relationship`…) and points each one at a library token.
- Types take the colour of their OpenCTI entity family (`--color-entities-*`), with the same type → family table as
  `opencti-front/src/utils/Colors.ts`.

### Gaps

| Need | What the library offers | What this app does |
|---|---|---|
| Graph canvas: nodes, edges, edge labels, minimap | Nothing (out of the library's scope today) | React Flow, styled with library tokens and `Icon`, `Button`, `Chip`, `Text` inside the nodes |
| Colours for STIX categories (SDO, SCO, SRO, Meta) | Entity families only | Family colour when the type has one, neutral `--icon-*` tokens otherwise; the category legend has no colour |
| A selectable list row (sidebar type list, saved views) | No List / ListItem | A minimal row (`src/shared/ui/row.css`) holding library `Text`, `Icon` and `IconButton` |
| Empty state | None | `EmptyState`, composed of `Icon`, `Text` and `Button` |
| Command palette | No command menu | `Dialog` holding a `Combobox` that stays open; its popover panel overflows the dialog's bottom edge |
| Non-modal side panel (the inspector stays open while the canvas is used) | `Drawer`, which is modal | A docked panel with library parts inside |
| Neutral accent chip ("Required", "Configurable") | `Chip` severities are risk levels | `severity="high"` for Required, `info` for Configurable and STIX |
| Keyboard shortcut display (`⌘K`) | No Kbd | Plain `Text` |
| Glyphs: filter, hash, braces, swap left-right, folder tree | Not in the icon set | Closest available glyph (`sliders-horizontal`, `chart-column`, `code-xml`, `arrow-up-down`, `list-tree`) |
| Border widths | No token | 1px hairlines, as the library's own components draw them |
| WCAG: `Chip` and `Switch` are flagged `fail` in `llms.txt` | — | Used as shipped; every chip and switch keeps a visible text label |

## Building for Production

To build the static application:

```bash
yarn build
```

The output will be in the `dist` directory.
