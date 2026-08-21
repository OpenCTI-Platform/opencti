## ADDED Requirements

### Requirement: Pure status-to-definition conversion
The system SHALL provide a pure function that converts an entity type's
existing `Status`/`StatusTemplate` configuration into an equivalent
`WorkflowDefinition`, along with diagnostics describing any ambiguity or
data-quality issue encountered.

#### Scenario: Well-formed status configuration
- **WHEN** the conversion function is run against an entity type whose
  statuses have unambiguous ordering and no conflicting names
- **THEN** it returns a `WorkflowDefinition` with states, an initial
  state, and transitions matching the existing status flow, and an empty
  diagnostics list

#### Scenario: Ambiguous or invalid status configuration
- **WHEN** the conversion function is run against an entity type whose
  statuses cannot be unambiguously converted (e.g. missing order, name
  conflicts)
- **THEN** it returns diagnostics describing each issue without throwing,
  and the caller can decide whether to proceed

### Requirement: Read-only migration preview
The system SHALL expose a read-only GraphQL query that returns the
conversion result (proposed `WorkflowDefinition` and diagnostics) for a
given entity type without persisting any change.

#### Scenario: Preview requested for an entity type
- **WHEN** a user with sufficient privileges queries the migration preview
  for an entity type
- **THEN** the system returns the proposed workflow definition and
  diagnostics using the pure conversion function, and makes no persisted
  changes

### Requirement: Versioned migration execution
The system SHALL provide a versioned migration that reuses the pure
conversion function to create `WorkflowDefinition` records and set the
corresponding `EntitySetting.workflow_id` references for entity types
whose status configuration is being migrated.

#### Scenario: Migration executed for an entity type
- **WHEN** the versioned migration runs for an entity type with a
  convertible status configuration
- **THEN** a `WorkflowDefinition` is created from the conversion result and
  the entity type's `EntitySetting.workflow_id` is set to reference it

#### Scenario: Migration skips entity types without a status configuration
- **WHEN** the versioned migration encounters an entity type with no
  existing status configuration
- **THEN** it skips that entity type without creating a workflow
  definition or modifying its entity setting
