---
name: create-module
description: "Use when: scaffolding a new backend entity type, domain module, GraphQL schema, resolvers, or STIX converter in opencti-graphql"
---

# Create Backend Module

## Prerequisites
- **Entity Name**: CamelCase (e.g., `MalwareAnalysis`).
- **Entity Type**: Constant (e.g., `ENTITY_TYPE_MALWARE_ANALYSIS`).
- **Parent/Category**: e.g., `ABSTRACT_STIX_DOMAIN_OBJECT`.

## Procedure

### Step 1 — Create Directory Structure
Create `opencti-platform/opencti-graphql/src/modules/<entityName>`.

### Step 2 — Create Schema File (`<name>.graphql`)
Define the Input, Type, Queries, and Mutations.

### Step 3 — Create Type Definition (`<name>-types.ts`)
Define TypeScript interfaces for StixObject, StoreEntity, and internal representations.
Export the `ENTITY_TYPE_X` constant here.

### Step 4 — Create Converter (`<name>-converter.ts`)
Implement `convert<Name>ToStix` function to map StoreEntity to StixObject.

### Step 5 — Create Domain Logic (`<name>-domain.ts`)
Implement CRUD functions: `findAll`, `findById`, `add<Name>`, `delete<Name>`.
Use `listEntities` and `createEntity` from `database/middleware`.

### Step 6 — Create Resolvers (`<name>-resolvers.ts`)
Map the GraphQL Query/Mutation fields to the functions in `<name>-domain.ts`.

### Step 7 — Create Module Definition (`<name>.ts`)
Implement `ModuleDefinition` interface.
Define attributes, relations, and register the definition using `registerDefinition`.

### Step 8a — Create GraphQL Registration File (`<name>-graphql.ts`)
Create a `<name>-graphql.ts` file in the module folder that imports the module schema/resolvers and calls `registerGraphqlSchema(...)`.

### Step 8b — Register Module in `src/modules/index.ts`
Add two distinct imports in `src/modules/index.ts`:
1. In the **`region registration modules`** section, import `./<entityName>/<entityName>` (module definition registration).
2. In the **`region graphql registration`** section, import `./<entityName>/<entityName>-graphql` (GraphQL endpoint registration).

### Step 8c — Update GraphQL Unions (if applicable)
If the entity belongs to a STIX union type (e.g., `StixObject`, `StixDomainObject`), add it to the relevant unions in `src/schema/opencti.graphql`.

### Step 8d — Regenerate Schema Types
Run `yarn build:schema` to regenerate TypeScript types from the updated schema.
