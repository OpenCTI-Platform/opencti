import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { getAvailableSettings } from '../../../src/modules/entitySetting/entitySetting-utils';
import { ABSTRACT_STIX_CORE_RELATIONSHIP, ABSTRACT_STIX_CYBER_OBSERVABLE } from '../../../src/schema/general';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INCIDENT, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { STIX_SIGHTING_RELATIONSHIP } from '../../../src/schema/stixSightingRelationship';

// `workflow_id` must be an available setting for every legacy-status entity type so it can be
// migrated to a published WorkflowDefinition, not just the entity types it was originally wired
// up for (StixSightingRelationship, DraftWorkspace). Without this, the `workflowDefinitionSet`
// GraphQL mutation fails with `UnsupportedError: This setting is not available for this entity`
// for every other type.
describe('getAvailableSettings — workflow_id availability', () => {
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

  it('grants workflow_id to StixSightingRelationship and DraftWorkspace', () => {
    expect(getAvailableSettings(STIX_SIGHTING_RELATIONSHIP)).toContain('workflow_id');
    expect(getAvailableSettings(ENTITY_TYPE_DRAFT_WORKSPACE)).toContain('workflow_id');
  });

  it('does not grant workflow_id to types with no Status/workflow support (e.g. cyber observables)', () => {
    expect(getAvailableSettings(ABSTRACT_STIX_CYBER_OBSERVABLE)).not.toContain('workflow_id');
  });
});
