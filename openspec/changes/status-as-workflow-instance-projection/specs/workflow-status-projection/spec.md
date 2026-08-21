## ADDED Requirements

### Requirement: Workflow instance as source of truth
For any entity type with a published `WorkflowDefinition`, the system SHALL
treat `WorkflowInstance.currentState` as the authoritative status value for
that entity, superseding the legacy `Status` value for read purposes.

#### Scenario: Entity type with published workflow
- **WHEN** an entity's type has a published `WorkflowDefinition`
- **THEN** the entity's effective status is resolved from its
  `WorkflowInstance.currentState`, not from a directly-set `Status` value

#### Scenario: Entity type without a workflow
- **WHEN** an entity's type has no published `WorkflowDefinition`
- **THEN** the entity's effective status continues to be the legacy
  `Status` (`x_opencti_workflow_id`) exactly as before this change

### Requirement: Deterministic status projection
The system SHALL derive `x_opencti_workflow_id` deterministically from
`WorkflowInstance.currentState` via a generated mapping of workflow states
to `Status` records, and SHALL write this projection through the normal
attribute-patch flow rather than a direct index write.

#### Scenario: Synchronous transition updates projection
- **WHEN** a workflow transition completes synchronously and changes
  `currentState`
- **THEN** the entity's `x_opencti_workflow_id` is updated via
  attribute-patch to the `Status` mapped to the new state, in the same
  logical operation, emitting the normal update stream event

#### Scenario: Asynchronous transition completion updates projection
- **WHEN** an asynchronous workflow action completes and advances
  `currentState`
- **THEN** the entity's `x_opencti_workflow_id` is updated via
  attribute-patch to reflect the new state once the async completion is
  recorded

#### Scenario: Fixed write order
- **WHEN** a workflow transition is applied
- **THEN** `WorkflowInstance.currentState` SHALL be persisted before the
  entity's `x_opencti_workflow_id` projection is updated

### Requirement: Workflow state ordering
The system SHALL assign an `order` to each state of a `WorkflowDefinition`,
computed topologically from the transition graph when an unambiguous order
exists, falling back to a manually specified order otherwise.

#### Scenario: Topological ordering possible
- **WHEN** a workflow definition's transitions form a graph with no cycles
  that would make relative ordering ambiguous
- **THEN** each state's `order` is computed from the minimum number of
  transitions required to reach it from the initial state

#### Scenario: Manual ordering fallback
- **WHEN** a workflow definition's transition graph does not yield an
  unambiguous topological order
- **THEN** the system uses a manually specified `order` value for each
  state instead

### Requirement: Full mapping guarantee on publish
When a `WorkflowDefinition` is published, the system SHALL ensure every
attached entity type has a `Status` record for each state in the
definition, creating any missing ones and removing `Status` records no
longer referenced by any state or any entity.

#### Scenario: Missing status created on publish
- **WHEN** a workflow definition is published and a state has no
  corresponding `Status` for one of its attached entity types
- **THEN** the system creates the missing `Status` for that entity type
  before the publish completes

#### Scenario: Orphaned status removed on republish
- **WHEN** a workflow definition is republished and a previously mapped
  state's `Status` is no longer referenced by any state in the new
  definition and no entity's `x_opencti_workflow_id` points to it
- **THEN** the system deletes that orphaned `Status` record

#### Scenario: No status creation on draft save
- **WHEN** a workflow definition draft (unpublished) is saved
- **THEN** the system SHALL NOT create or modify any `Status` records

### Requirement: Deletion protection for referenced statuses
The system SHALL prevent deletion of a `Status` or `StatusTemplate` that is
referenced by a published `WorkflowDefinition`.

#### Scenario: Attempt to delete a referenced status
- **WHEN** a user attempts to delete a `Status` or `StatusTemplate` that a
  published workflow definition maps to
- **THEN** the deletion is rejected with an error identifying the
  referencing workflow

### Requirement: Read-repair for projection divergence
The system SHALL detect and correct divergence between
`WorkflowInstance.currentState` and the entity's projected
`x_opencti_workflow_id` when reading workflow instance data.

#### Scenario: Divergence detected on read
- **WHEN** an entity's `x_opencti_workflow_id` does not match the `Status`
  mapped to its `WorkflowInstance.currentState` at read time
- **THEN** the system corrects the projected `x_opencti_workflow_id` to
  match the current state before returning the result
