import { describe, expect, it } from 'vitest';
import { schemaTypesDefinition, withinRegistration } from '../../../src/schema/schema-types';

// Nothing else is imported: the types registry starts empty and writable.
describe('Types registry usage protection', () => {
  it('should stay writable through registration reads and lock on the first other read', () => {
    schemaTypesDefinition.register('Parent', ['Child-A']);
    expect(withinRegistration(() => schemaTypesDefinition.isTypeIncludedIn('Child-A', 'Parent'))).toBe(true);
    expect(withinRegistration(() => schemaTypesDefinition.get('Parent'))).toEqual(['Child-A']);
    schemaTypesDefinition.add('Parent', 'Child-B');

    expect(schemaTypesDefinition.hasChildren('Parent')).toBe(true);
    expect(() => schemaTypesDefinition.add('Parent', 'Child-C')).toThrow('Register types use after usage');
    expect(() => schemaTypesDefinition.register('Other-Parent', [])).toThrow('Register types use after usage');
    expect(schemaTypesDefinition.get('Parent')).toEqual(['Child-A', 'Child-B']);
  });
});
