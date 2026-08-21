## ADDED Requirements

### Requirement: Tolerant direct status writes
The system SHALL continue to allow direct writes to `Status`
(`x_opencti_workflow_id`) from existing flows (playbooks, requestAccess,
the public API, the sync manager) for entity types with a configured
workflow, rather than blocking them.

#### Scenario: Direct write from an existing flow
- **WHEN** a playbook, requestAccess flow, public API call, or sync
  manager operation directly sets `x_opencti_workflow_id` on an entity
  with a configured workflow
- **THEN** the write succeeds and is not rejected by the workflow engine

### Requirement: External state jump synchronization
When a direct `Status` write occurs on an entity with a `WorkflowInstance`,
the system SHALL synchronize `WorkflowInstance.currentState` to match the
new status and record the change as an external state jump in the
workflow instance's history.

#### Scenario: Direct write triggers instance sync
- **WHEN** a direct write sets an entity's `x_opencti_workflow_id` to a
  `Status` mapped to a different workflow state than the current
  `WorkflowInstance.currentState`
- **THEN** the system updates `WorkflowInstance.currentState` to the
  mapped state and appends a history entry with event type
  `event_external`

#### Scenario: Direct write to the already-current status
- **WHEN** a direct write sets an entity's `x_opencti_workflow_id` to the
  `Status` already mapped to its current `WorkflowInstance.currentState`
- **THEN** no additional history entry is recorded
