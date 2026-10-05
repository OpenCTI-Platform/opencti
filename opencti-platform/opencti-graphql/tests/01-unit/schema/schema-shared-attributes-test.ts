import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { ENTITY_TYPE_SOURCE_RECOMMENDATION } from '../../../src/modules/sourceIntelligence/sourceIntelligence-types';

// The platform refuses to load its schema when one attribute name has two types or one label names two attributes.
// The investigation run registers these names as objects and owns these labels.
const OBJECT_ATTRIBUTE_NAMES = ['evidence'];
const LABEL_OWNERS: Record<string, string> = {
  Evidence: 'evidence',
};

describe('Attributes shared across modules', () => {
  it.each(OBJECT_ATTRIBUTE_NAMES)('should register %s as an object attribute only', (name) => {
    expect(schemaAttributesDefinition.getAttributeByName(name)?.type ?? 'object').toBe('object');
  });

  it.each(Object.entries(LABEL_OWNERS))('should give the label %s to the %s attribute only', (label, name) => {
    const names = schemaAttributesDefinition.getAllAttributes().filter((attribute) => attribute.label === label).map((attribute) => attribute.name);
    expect(names.filter((attributeName) => attributeName !== name)).toEqual([]);
  });

  it('should register the source recommendation evidence under its own name', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_SOURCE_RECOMMENDATION, 'recommendation_evidence'))
      .toMatchObject({ type: 'string', label: 'Recommendation evidence' });
  });
});
