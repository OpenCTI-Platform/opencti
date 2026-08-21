## ADDED Requirements

### Requirement: User-facing apply-transition action
The system SHALL provide a user-facing action to apply an allowed workflow
transition on an entity, disabling the action while a transition is
pending and displaying an error message if the transition fails.

#### Scenario: Transition pending
- **WHEN** a user triggers a workflow transition on an entity and it has
  not yet completed
- **THEN** the transition action is disabled and shows a pending
  indicator until the transition completes

#### Scenario: Transition fails
- **WHEN** a triggered workflow transition fails
- **THEN** the system displays an error message describing the failure
  and re-enables the transition action

#### Scenario: Apply transition when only legacy status exists
- **WHEN** a user applies a transition on an entity that has a legacy
  `Status` but no `WorkflowInstance` yet
- **THEN** the system creates a `WorkflowInstance` for the entity before
  applying the transition

### Requirement: Bypass update modes
The system SHALL offer two status-update modes for a single entity: update
the status without applying any transition, or update the status by
applying the current state's onExit and the target state's onEnter
actions.

#### Scenario: Update without transition actions
- **WHEN** a user selects "update status without applying any
  transitions" and picks a target status
- **THEN** the entity's status changes to the target without executing
  any onExit/onEnter actions, and existing `WorkflowInstance` data (or
  `Status`) is updated accordingly

#### Scenario: Update applying transition actions
- **WHEN** a user selects "update status applying current status onExit
  and target status onEnter" and picks a target status
- **THEN** the system executes the current state's onExit actions and the
  target state's onEnter actions as part of the update

#### Scenario: Update creates instance when only status exists
- **WHEN** either update mode is used on an entity with a legacy `Status`
  but no `WorkflowInstance`
- **THEN** the system creates a `WorkflowInstance` for the entity as part
  of the update

### Requirement: Mass operation status updates
The system SHALL support the same two update modes (status-only,
status-with-transition-actions) for mass status updates and for playbook
status actions, executed as background tasks.

#### Scenario: Mass status update without transitions
- **WHEN** a user runs a mass operation to update status on multiple
  entities without applying transitions
- **THEN** a background task updates each entity's status without
  executing onExit/onEnter actions

#### Scenario: Mass status update with transitions
- **WHEN** a user runs a mass operation to update status on multiple
  entities applying transition actions
- **THEN** a background task updates each entity's status and executes
  the corresponding onExit/onEnter actions per entity

#### Scenario: Playbook status action mode selection
- **WHEN** a playbook status action is configured with one of the two
  update modes
- **THEN** it applies status changes to matching entities using the
  selected mode, consistent with the mass operation behavior
