import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { authorizedMembers } from '../../../../src/schema/attribute-definition';
import { AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES } from '../../../../src/utils/authorizedMembers';
import { ENTITY_TYPE_HUNT } from '../../../../src/modules/hunt/hunt-types';
import { ENTITY_TYPE_HUNT_RUN } from '../../../../src/modules/hunt/huntRun/huntRun-types';

// Runs inherit the markings and organizations of their hunt only: restricting hunts to members would need their runs
// to apply that restriction on every read and every action first
describe('Hunt access', () => {
  it('should not let a hunt or a hunt run be restricted to members', () => {
    expect(AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES).not.toContain(ENTITY_TYPE_HUNT);
    expect(AUTHORIZED_MEMBERS_SUPPORTED_ENTITY_TYPES).not.toContain(ENTITY_TYPE_HUNT_RUN);
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT, authorizedMembers.name)).toBeUndefined();
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, authorizedMembers.name)).toBeUndefined();
  });
});
