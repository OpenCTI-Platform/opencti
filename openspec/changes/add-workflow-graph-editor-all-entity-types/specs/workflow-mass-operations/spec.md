## ADDED Requirements

### Requirement: Mass real-transition workflow apply
The system SHALL allow a user with knowledge update rights to apply a
named workflow transition event to a bulk selection of entities of the
same type, following the same allowed-transition graph, condition
evaluation, and history recording as the single-entity transition trigger.
Elements in the selection that are not currently in an eligible state for
the chosen transition SHALL be skipped and counted as errors rather than
aborting the whole operation.

#### Scenario: Mass transition applies to eligible elements
- **WHEN** a user with knowledge update rights selects a bulk set of
  entities of the same type and applies a workflow transition event
- **THEN** each selected entity currently in an eligible state for that
  transition moves to the transition's target state, with the same
  condition evaluation and history recording as the single-entity path

#### Scenario: Mass transition tolerates ineligible elements in the selection
- **WHEN** the bulk selection includes entities that are not currently in
  an eligible state for the chosen transition
- **THEN** those entities are skipped, an error is recorded per skipped
  entity, and the operation still completes for the eligible entities

#### Scenario: Mass transition respects existing authorization
- **WHEN** a user without knowledge update rights attempts to apply a mass
  workflow transition
- **THEN** the operation is rejected, consistent with the authorization
  required by the single-entity transition trigger

### Requirement: Mass bypass forced status update
The system SHALL allow a bypass user to force a bulk selection of entities
of the same type directly to a chosen target status, optionally applying
that status's onEnter/onExit actions, without requiring an allowed
transition edge between each entity's current state and the target state.

#### Scenario: Bypass user forces a bulk status update
- **WHEN** a bypass user selects a bulk set of entities of the same type
  and forces them to a target status, with the apply-actions option
  enabled
- **THEN** each selected entity's status is set to the target status and
  the target status's configured actions run, regardless of whether an
  allowed transition edge exists from each entity's current state

#### Scenario: Non-bypass users cannot access the forced mass update option
- **WHEN** a user without bypass rights views the bulk mass-edit options
  for a workflow-enabled entity type
- **THEN** the forced status update option is not available to them
