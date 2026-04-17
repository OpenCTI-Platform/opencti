# Module Architecture (CRITICAL - NEW MODULES ONLY)

All new domain entities must be created in `src/modules/<entity-name>/`.
This is a strict departure from the old scattered structure (resolvers/, domain/, schema/ folders).

**A module MUST contain:**
1.  **Schema** (`.graphql`): Defines the API model.
2.  **Resolvers** (`-resolver.ts`): Bridges GraphQL to Domain.
3.  **Domain** (`-domain.ts`): Contains business logic.
4.  **Types** (`-types.ts`): TypeScript definitions.
5.  **Converter** (`-converter.ts`): Internal <-> STIX conversion.
6.  **Definition** (`<name>.ts`): Registers the module in `ModuleDefinition`.

**Registration Steps:**
1.  Create the directory and files.
2.  Add a **type mapper** entry in `graphql-codegen.yml` for the new entity type (`.graphql` files are auto-discovered via glob — no schema path entry needed).
3.  Register in `src/modules/index.ts` by adding an import of the module definition file (side-effect import — the file calls `registerDefinition`).
4.  Add to `opencti.graphql` unions.
