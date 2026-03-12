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

### Step 8 — Register Module
1. Create `index.ts` in the module folder.
2. Import the module in `src/modules/index.ts`.
3. Add the new types to unions in `src/schema/opencti.graphql` if applicable.
4. Run `yarn build:schema` to update types.
