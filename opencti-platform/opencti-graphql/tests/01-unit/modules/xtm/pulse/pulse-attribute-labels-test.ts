import { describe, expect, it } from 'vitest';
import '../../../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../../../src/schema/schema-attributes';
import { PULSE_ATTRIBUTE_UNIQUENESS } from '../../../../../src/modules/xtm/pulse/pulse-types';

describe('Threat Pulse attribute labels', () => {
  it('should label the community uniqueness of Threat Pulse with its prefix', () => {
    expect(schemaAttributesDefinition.getAttributeByName(PULSE_ATTRIBUTE_UNIQUENESS)?.label).toBe('Pulse community uniqueness');
  });

  // The platform refuses to load its schema when one label names two attributes: the source scorecard owns the plain label
  it('should leave the plain community uniqueness label to the source scorecard', () => {
    const names = schemaAttributesDefinition.getAllAttributes().filter((attribute) => attribute.label === 'Community uniqueness').map((attribute) => attribute.name);
    expect(names.filter((name) => name !== 'community_uniqueness')).toEqual([]);
  });
});
