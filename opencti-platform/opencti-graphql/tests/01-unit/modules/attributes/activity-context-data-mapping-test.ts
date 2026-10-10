import { describe, expect, it, vi } from 'vitest';

// Every feature flag disabled, as on a platform started without dev features
vi.mock('../../../../src/config/conf', async (importOriginal: any) => ({
  ...(await importOriginal()),
  isFeatureEnabled: () => false,
}));

import { registerModules } from '../../../../src/composition-root';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_ACTIVITY } from '../../../../src/schema/internalObject';
import type { ObjectAttribute } from '../../../../src/schema/attribute-definition';

// Registers the abstract types too, among them the Activity attributes
registerModules();

describe('Activity context data mapping without feature flags', () => {
  const contextDataAttribute = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_ACTIVITY, 'context_data') as ObjectAttribute;
  const mappedFields = contextDataAttribute.mappings.map(({ name }) => name);

  it('should not map the fields of a disabled feature', () => {
    expect(mappedFields).not.toContain('lock_source');
  });

  it('should map the reason of a logout, given by the end of a session over its maximum lifetime', () => {
    // The mapping of the context data is strict: without the field, the indexing of the logout fails
    expect(mappedFields).toContain('reason');
  });
});
