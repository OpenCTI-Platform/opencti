import { describe, expect, it } from 'vitest';
import { filterUserIdAttributes } from '../../../src/utils/merge-user-plan';
import { ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { AttributeDefinition } from '../../../src/schema/attribute-definition';

// This test is the "auto-adaptivity proof" required by the PoC: it demonstrates that
// `filterUserIdAttributes` (the core of the schema-driven discovery used by
// `script-merge-user-plan.js`) picks up ANY new id-format attribute pointing to a User
// without a single line of code being changed in the merge-plan module. Only the fixture
// list below is extended, exactly like a new attribute would be added to the real schema
// (e.g. in src/schema/attribute-definition.ts) by an unrelated feature.
describe('Merge user plan - schema-driven auto-adaptivity', () => {
  it('does not know any attribute name upfront, only the generic "id pointing to User" rule', () => {
    const existingAttributes: AttributeDefinition[] = [
      { name: 'creator_id', label: 'Creators', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], update: true, mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: true },
      { name: 'name', label: 'Name', type: 'string', format: 'short', mandatoryType: 'no', editDefault: false, multiple: false, upsert: false, isFilterable: true },
      { name: 'object-marking', label: 'Marking', type: 'string', format: 'id', entityTypes: ['Marking-Definition'], mandatoryType: 'no', editDefault: false, multiple: true, upsert: true, isFilterable: false },
    ];
    const before = filterUserIdAttributes(existingAttributes);
    expect(before.map((a) => a.name)).toEqual(['creator_id']);

    // Simulate a brand new attribute being registered by an unrelated future feature
    // (e.g. a "reviewer_id" field on some entity type), without touching merge-user-plan.ts.
    const brandNewAttribute: AttributeDefinition = {
      name: 'reviewer_id', label: 'Reviewer', type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], mandatoryType: 'no', editDefault: false, multiple: false, upsert: true, isFilterable: true,
    };
    const after = filterUserIdAttributes([...existingAttributes, brandNewAttribute]);

    // The new field appears alone, no other change was required.
    expect(after.map((a) => a.name)).toEqual(['creator_id', 'reviewer_id']);
  });
});
