# OpenCTI Schema Viz

A React Flow-based tool to visualize the OpenCTI Graph database schema. It renders Entities, Relationships, and Attributes in a structured, hierarchical graph.

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

Open [http://localhost:5173](http://localhost:5173) in your browser.

## Building for Production

To build the static application:

```bash
yarn build
```

The output will be in the `dist` directory.
