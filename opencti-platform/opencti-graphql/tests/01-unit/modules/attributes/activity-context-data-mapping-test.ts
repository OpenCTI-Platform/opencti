import { describe, expect, it, vi } from 'vitest';

// Every feature flag disabled, as on a platform started without dev features
vi.mock('../../../../src/config/conf', async (importOriginal: any) => ({
  ...(await importOriginal()),
  isFeatureEnabled: () => false,
}));

import '../../../../src/modules/attributes/internalObject-registrationAttributes';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_ACTIVITY } from '../../../../src/schema/internalObject';
import type { ObjectAttribute } from '../../../../src/schema/attribute-definition';

describe('Activity context data mapping without feature flags', () => {
  const contextDataAttribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_ACTIVITY, 'context_data') as ObjectAttribute;
  const mappedFields = contextDataAttribute.mappings.map(({ name }) => name);

  it('should map the fields of a lock, given by the local authentication lockout', () => {
    // The mapping of the context data is strict: without the fields, the indexing of the lock fails
    expect(mappedFields).toEqual(expect.arrayContaining(['lock_type', 'lock_duration', 'max_attempts', 'lock_source']));
  });

  it('should map the reason of a logout, given by the end of a session over its maximum lifetime', () => {
    // The mapping of the context data is strict: without the field, the indexing of the logout fails
    expect(mappedFields).toContain('reason');
  });
});
