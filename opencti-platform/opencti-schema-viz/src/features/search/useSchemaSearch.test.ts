import { describe, expect, it } from 'vitest';
import { buildFixtureSchema } from '../../test/fixtures';
import { searchSchema } from './useSchemaSearch';

const schema = buildFixtureSchema();

describe('searchSchema', () => {
  it('ranks exact, then prefix, then word prefix matches', () => {
    expect(searchSchema(schema, 'threat-actor').types.map((hit) => hit.typeId)).toEqual(['Threat-Actor', 'Threat-Actor-Group', 'Threat-Actor-Individual']);
    expect(searchSchema(schema, 'group').types.map((hit) => hit.typeId)).toEqual(['Threat-Actor-Group']);
  });

  it('ignores separators and case', () => {
    expect(searchSchema(schema, 'THREATACTORG').types.map((hit) => hit.typeId)).toEqual(['Threat-Actor-Group']);
  });

  it('finds attributes and where they are declared', () => {
    expect(searchSchema(schema, 'is_fam').attributes).toEqual([{ name: 'is_family', declaredBy: [{ typeId: 'Malware', typeCount: 1 }] }]);
    expect(searchSchema(schema, 'aliases').attributes[0].declaredBy).toEqual([{ typeId: 'Threat-Actor', typeCount: 3 }]);
  });

  it('returns nothing for a blank term', () => {
    expect(searchSchema(schema, '   ')).toEqual({ types: [], attributes: [] });
  });
});
