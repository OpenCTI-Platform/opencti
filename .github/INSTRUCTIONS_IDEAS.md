# AI Instructions & Skills Ideas

This document tracks potential additions to the `.github/instructions` and `.github/skills` directories. Feel free to submit your own.

## Instructions (Declarative Knowledge)

### Backend (`opencti-graphql`)
- **Rules Engine**:
  - **Concept**: Explanation of how inference rules work (Definition + Implementation).
  - **Location**: `src/rules/`.
  - **Key Files**: `RuleDefinition.ts`, `Rule.ts`, `rules-definition.ts`.

### Frontend (`opencti-front`)
- **Entity Relationships View**:
  - **Pattern**: Usage of `EntityStixCoreRelationships` and variations.
  - **Context**: How to add a relationship tab/list to an entity view.

## Skills (Procedural Playbooks)

### Backend
- **`create-inference-rule`**:
  - **Action**: Adds a new logic rule to the platform.
  - **Steps**:
    1. Create directory `src/rules/<rule-name>`.
    2. Create `Definition.ts` (Metadata, Scopes).
    3. Create `Rule.ts` (Logic, Apply/Clean functions).
    4. Register in `src/rules/rules-definition.ts`.

### Full Stack
- **`add-entity-field`**:
  - **Action**: Adds a new field to an existing entity (E2E).
  - **Backend Steps**:
    1. Modify `.graphql` schema.
    2. Update `types.ts`.
    3. Update `domain.ts` (validation).
    4. Create migration.
  - **Frontend Steps**:
    1. Update Fragment.
    2. Update Creation/Edition forms.
    3. Update View component.

### Automation
- **`create-python-script`**:
  - **Action**: Creates a standalone Python automation script.
  - **Template**:
    - Import `pycti`.
    - Env var loading.
    - Client initialization.
    - Boilerplate for common operations (create, search, update).
