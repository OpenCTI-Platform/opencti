import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { getAvailableSettings } from '../../../src/modules/entitySetting/entitySetting-utils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../../src/schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';

// Task 6/Task 13 (status-as-workflow-instance-projection): `workflow_id` must be an available
// setting for every legacy-status entity type Task 6's migration targets, not just the two types
// (StixSightingRelationship, DraftWorkspace) Task 5 originally wired up. Without this, both the
// `workflowDefinitionSet` GraphQL mutation AND Task 6's own migration function (which reuses the
// same `setWorkflowDefinition` -> `updateAttribute` write path) fail with
// `UnsupportedError: This setting is not available for this entity` for every other type
// (confirmed live against a running local instance).
describe('getAvailableSettings — workflow_id availability (Task 6/13 migration-availability fix)', () => {
  it('grants workflow_id to a container SDO type (e.g. Report)', () => {
    expect(getAvailableSettings(ENTITY_TYPE_CONTAINER_REPORT)).toContain('workflow_id');
  });

  it('grants workflow_id to a template-object SDO type (e.g. Incident, Malware)', () => {
    expect(getAvailableSettings(ENTITY_TYPE_INCIDENT)).toContain('workflow_id');
    expect(getAvailableSettings(ENTITY_TYPE_MALWARE)).toContain('workflow_id');
  });

  it('grants workflow_id to a stix-core-relationship type', () => {
    expect(getAvailableSettings(ABSTRACT_STIX_CORE_RELATIONSHIP)).toContain('workflow_id');
  });

  it('still grants workflow_id to the two types Task 5 originally wired up', () => {
    expect(getAvailableSettings(STIX_SIGHTING_RELATIONSHIP)).toContain('workflow_id');
    expect(getAvailableSettings(ENTITY_TYPE_DRAFT_WORKSPACE)).toContain('workflow_id');
  });

  it('does not grant workflow_id to types with no Status/workflow support (e.g. cyber observables)', () => {
    expect(getAvailableSettings(ABSTRACT_STIX_CYBER_OBSERVABLE)).not.toContain('workflow_id');
  });
});
