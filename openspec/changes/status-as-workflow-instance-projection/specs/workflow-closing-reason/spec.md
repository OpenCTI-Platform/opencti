## ADDED Requirements

### Requirement: Closing reason field
The system SHALL provide a closing-reason field on entities, backed by a
backend implementation modeled on the existing comments feature, with its
own dedicated UI distinct from the comments UI.

#### Scenario: Setting a closing reason
- **WHEN** a user closes an entity (transitions it to a closing state) and
  provides a closing reason
- **THEN** the closing reason is persisted and associated with that
  entity, following the same storage pattern used for comments

#### Scenario: Displaying a closing reason
- **WHEN** an entity with a persisted closing reason is viewed
- **THEN** its dedicated closing-reason UI displays the reason, separate
  from the comments section
