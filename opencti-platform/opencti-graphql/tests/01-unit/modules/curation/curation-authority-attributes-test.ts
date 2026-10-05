import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { curationAuthorityAttributes, validateFieldAuthorityRules } from '../../../../src/modules/curation/curation-settings';
import { ENTITY_TYPE_CONTAINER_REPORT, ENTITY_TYPE_INTRUSION_SET } from '../../../../src/schema/stixDomainObject';

describe('field authority attributes', () => {
  it('offers the business attributes of the curated types, the ones a rule may target', () => {
    const offered = curationAuthorityAttributes([ENTITY_TYPE_INTRUSION_SET, ENTITY_TYPE_CONTAINER_REPORT]);
    // A container is not curated: it has no entry.
    expect(offered.map((entry) => entry.entity_type)).toEqual([ENTITY_TYPE_INTRUSION_SET]);
    const names = offered[0].attributes.map((attribute) => attribute.name);
    expect(names).toEqual(expect.arrayContaining(['name', 'description', 'aliases']));
    expect(names.some((name) => name.startsWith('i_'))).toBe(false);
    expect(names).not.toContain('internal_id');
    expect(names).not.toContain('updated_at');
    expect(offered[0].attributes.find((attribute) => attribute.name === 'description')?.label).toBe('Description');
    // Every offered attribute is accepted by the validation of the rules.
    const sources = [{ source_type: 'author', source_id: 'identity-id' }];
    expect(() => validateFieldAuthorityRules(names.map((attribute) => ({ entity_type: ENTITY_TYPE_INTRUSION_SET, attribute, sources })) as never)).not.toThrow();
    expect(() => validateFieldAuthorityRules([{ entity_type: ENTITY_TYPE_INTRUSION_SET, attribute: 'internal_id', sources }] as never)).toThrow();
  });
});
