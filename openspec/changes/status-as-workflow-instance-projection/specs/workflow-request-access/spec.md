## ADDED Requirements

### Requirement: Dual workflow definitions per entity type
The system SHALL allow an entity type to have two distinct published
`WorkflowDefinition`s: a standard definition and a `request_access`
definition, and SHALL route each entity to the appropriate one based on
its `request_access` scope.

#### Scenario: Entity created via request_access
- **WHEN** an entity of a type with both a standard and a
  `request_access` workflow definition is created within `request_access`
  scope
- **THEN** its `WorkflowInstance` is initialized against the
  `request_access` definition

#### Scenario: Entity created outside request_access
- **WHEN** an entity of the same type is created outside `request_access`
  scope
- **THEN** its `WorkflowInstance` is initialized against the standard
  definition

#### Scenario: Entity type with only a standard definition
- **WHEN** an entity type has no dedicated `request_access` workflow
  definition
- **THEN** all entities of that type, including those created via
  `request_access`, use the standard definition
