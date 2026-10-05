import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { ENTITY_TYPE_SOURCE_RECOMMENDATION } from '../../../src/modules/sourceIntelligence/sourceIntelligence-types';
import { ENTITY_TYPE_HUNT_RUN } from '../../../src/modules/hunt/huntRun/huntRun-types';

// The platform refuses to load its schema when one attribute name has two types or one label names two attributes.
// The investigation run registers these names as objects and owns these labels.
const OBJECT_ATTRIBUTE_NAMES = ['evidence', 'analyst_feedback'];
const LABEL_OWNERS: Record<string, string> = {
  Evidence: 'evidence',
  'Analyst feedback': 'analyst_feedback',
  'Run status': 'run_status',
  'Run trigger': 'run_trigger',
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

  it('should register the hunt run feedback and labels under their own names', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, 'hunt_analyst_feedback')).toMatchObject({ type: 'string', label: 'Hunt analyst feedback' });
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, 'hunt_run_status')).toMatchObject({ label: 'Hunt run status' });
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, 'hunt_run_trigger')).toMatchObject({ label: 'Hunt run trigger' });
  });
});
