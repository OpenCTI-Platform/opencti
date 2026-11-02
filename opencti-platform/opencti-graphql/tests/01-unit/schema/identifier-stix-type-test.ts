import { describe, expect, it } from 'vitest';
import { isSupportedStixType, registerModelIdentifier } from '../../../src/schema/identifier';

// isSupportedStixType keeps the supported types between calls: a contribution registered later
// (a module loaded after a first StixId parse) must still be seen
describe('isSupportedStixType', () => {
  // The types no contribution defines under its STIX name, added by hand to the set
  it.each(['identity', 'location', 'file', 'relationship', 'sighting', 'threat-actor'])('should accept %s', (stixType) => {
    expect(isSupportedStixType(stixType)).toBe(true);
  });
  it('should accept a type registered after a first call', () => {
    expect(isSupportedStixType('relationship')).toBe(true);
    expect(isSupportedStixType('x-late-registered-type')).toBe(false);

    registerModelIdentifier({ definition: { 'X-Late-Registered-Type': [{ src: 'name' }] }, resolvers: {} });

    expect(isSupportedStixType('x-late-registered-type')).toBe(true);
    expect(isSupportedStixType('X-Late-Registered-Type')).toBe(false);
    expect(isSupportedStixType('relationship')).toBe(true);
  });
});
