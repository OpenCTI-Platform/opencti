## ADDED Requirements

### Requirement: Generalized workflow editor routing
The entity type customization Workflow settings tab SHALL render the
generic workflow graph editor for any entity type for which
`isWorkflowUiEnabledForType` returns true, instead of only for
`DraftWorkspace`. For entity types where it returns false, the tab SHALL
continue to render the legacy global workflow settings card.

#### Scenario: Workflow tab shows graph editor for a non-DraftWorkspace type
- **WHEN** an admin opens the Workflow tab for an entity type other than
  `DraftWorkspace` while the `ENTITIES_WORKFLOW` feature is enabled
- **THEN** the graph editor is rendered with that entity type's workflow
  data, not the legacy global workflow settings card

#### Scenario: Workflow tab falls back to legacy card when the feature is disabled
- **WHEN** an admin opens the Workflow tab for an entity type other than
  `DraftWorkspace` while the `ENTITIES_WORKFLOW` feature is disabled
- **THEN** the legacy global workflow settings card is rendered, unchanged
  from current behavior

#### Scenario: DraftWorkspace behavior is unchanged
- **WHEN** an admin opens the Workflow tab for the `DraftWorkspace` entity
  type
- **THEN** the graph editor is rendered exactly as it is today, regardless
  of the `ENTITIES_WORKFLOW` feature state

### Requirement: Global/RequestAccess scope switcher in the editor
The workflow graph editor SHALL let an admin switch between editing the
`GLOBAL`-scope workflow definition and the `RequestAccess`-scope workflow
definition for the current entity type, within the same editor surface.
The `RequestAccess` scope option SHALL only be offered when the entity
type has request-access workflow configuration available (Enterprise
Edition and `request_access_workflow` present in the type's available
settings).

#### Scenario: RequestAccess scope option hidden without EE/request-access config
- **WHEN** an admin opens the workflow editor for an entity type without
  `request_access_workflow` in its available settings, or without an
  Enterprise Edition license
- **THEN** only the `GLOBAL` scope is selectable in the editor

#### Scenario: RequestAccess scope option available with EE/request-access config
- **WHEN** an admin opens the workflow editor for an entity type with
  `request_access_workflow` available and an active Enterprise Edition
  license
- **THEN** both `GLOBAL` and `RequestAccess` scopes are selectable, and
  switching between them loads the corresponding workflow definition

### Requirement: Confirm-gated legacy status migration
The first time the workflow editor is opened for an entity type/scope
combination that has no published `WorkflowDefinition` yet but has legacy
`Status` data, the system SHALL show a confirmation step with migration
preview diagnostics before creating and publishing a `WorkflowDefinition`
from that legacy data. The migration SHALL NOT run automatically without
this explicit confirmation.

#### Scenario: First visit with legacy data prompts for confirmation
- **WHEN** an admin opens the workflow editor for a type/scope that has
  legacy `Status` data and no existing `WorkflowDefinition`
- **THEN** the system shows a confirmation dialog with the migration
  preview diagnostics and does not create a `WorkflowDefinition` until the
  admin explicitly confirms

#### Scenario: Confirming migration creates and publishes the definition
- **WHEN** an admin confirms the migration prompt
- **THEN** a `WorkflowDefinition` is created and published from the legacy
  `Status` data for that type/scope, and the editor then displays it

#### Scenario: Subsequent visits skip the confirmation
- **WHEN** an admin opens the workflow editor for a type/scope that
  already has a published `WorkflowDefinition` (including one created by a
  prior migration confirmation)
- **THEN** the editor opens directly with no migration confirmation step

### Requirement: RequestAccess-scope legacy status migration support
The legacy-status-to-workflow migration SHALL support converting
`RequestAccess`-scoped `Status` data into a published `WorkflowDefinition`,
in addition to the existing `GLOBAL`-scope support.

#### Scenario: Migrating RequestAccess-scoped legacy data succeeds
- **WHEN** the migration is run for an entity type/scope of `RequestAccess`
  that has legacy `RequestAccess`-scoped `Status` data and no existing
  `WorkflowDefinition` for that scope
- **THEN** a `WorkflowDefinition` is created and published from that data,
  without raising an error

#### Scenario: RFI approve/decline stays in sync with a RequestAccess-scope definition
- **WHEN** a `RequestAccess`-scope `WorkflowDefinition` is published for
  `Case-Rfi`, and an admin subsequently approves or declines a Request For
  Information
- **THEN** the resulting `WorkflowInstance` for that RFI reflects the
  approved/declined state and history, resolved against the
  `RequestAccess`-scope definition (not silently left unsynced by
  resolving the wrong scope)
