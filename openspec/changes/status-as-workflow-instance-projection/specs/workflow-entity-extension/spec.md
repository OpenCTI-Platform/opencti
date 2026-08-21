## ADDED Requirements

### Requirement: Eager workflow instance creation
The system SHALL generalize `initializeEntityWorkflow` to run for any
entity type at creation time, creating a real `WorkflowInstance`
immediately when the entity's type has a published `WorkflowDefinition`,
and remaining a no-op otherwise.

#### Scenario: New entity of workflow-enabled type
- **WHEN** an entity of a type with a published `WorkflowDefinition` is
  created
- **THEN** a real, persisted `WorkflowInstance` exists for that entity
  immediately after creation, without waiting for a first transition

#### Scenario: New entity of type without workflow
- **WHEN** an entity of a type with no published `WorkflowDefinition` is
  created
- **THEN** no `WorkflowInstance` is created and the entity behaves exactly
  as it does today

### Requirement: Lazy backfill for pre-existing entities
The system SHALL persist a real `WorkflowInstance` for a pre-existing
entity the first time its workflow status is read, instead of only
fabricating an in-memory placeholder.

#### Scenario: First read of pre-existing entity's workflow status
- **WHEN** `getWorkflowInstance` is called for an entity that has no
  `WorkflowInstance` yet but whose type has a published
  `WorkflowDefinition`
- **THEN** the system creates and persists a real `WorkflowInstance` at
  the definition's initial state and returns it

#### Scenario: Idempotent backfill
- **WHEN** `getWorkflowInstance` is called a second time for the same
  entity after the backfill in the previous scenario
- **THEN** the existing persisted `WorkflowInstance` is returned and no
  duplicate instance is created

### Requirement: Generalized workflow status filtering
The system SHALL generalize workflow-status filter resolution from the
`DraftWorkspace`-only implementation into the shared special-filter-key
resolution used for legacy status, and register it for every entity type
with a configured workflow.

#### Scenario: Filtering a workflow-enabled entity type by status
- **WHEN** a list query filters by status for an entity type that has a
  configured workflow
- **THEN** the filter resolves matching entities by their
  `WorkflowInstance.currentState` and rewrites the filter as an entity-id
  list, following the same resolution pattern as the legacy status filter

#### Scenario: Filtering an entity type without a workflow
- **WHEN** a list query filters by status for an entity type with no
  configured workflow
- **THEN** the filter continues to resolve against the legacy `Status`
  field exactly as before this change

### Requirement: Feature-flagged rollout
The system SHALL gate the extended workflow engine (backend wiring and
frontend UI) for entity types other than `DraftWorkspace` behind a single
`ENTITIES_WORKFLOW` feature flag.

#### Scenario: Flag disabled
- **WHEN** `ENTITIES_WORKFLOW` is disabled
- **THEN** only `DraftWorkspace` uses the workflow engine and UI; all
  other entity types behave as before this change

#### Scenario: Flag enabled
- **WHEN** `ENTITIES_WORKFLOW` is enabled
- **THEN** entity types with a published workflow definition use the
  workflow engine and UI as described in this capability

### Requirement: Draft-only actions hidden for non-draft entities
The system SHALL hide draft-only workflow actions (validate draft,
Authorized Members transition actions) for entity types other than
`DraftWorkspace`, and SHALL skip their validation checks for those types.

#### Scenario: Non-draft, non-container entity
- **WHEN** the workflow UI is shown for an entity type that is not
  `DraftWorkspace` and not a Container
- **THEN** the validate-draft action and Authorized Members actions are
  not displayed, and no validation error related to them is raised
