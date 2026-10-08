import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import { ENTITY_TYPE_HUNT_RUN } from '../../../../src/modules/hunt/huntRun/huntRun-types';

// The platform refuses to load its schema when one attribute name has two types or one label names two attributes:
// the hunt run keeps its feedback, status and trigger under names and labels of its own.
const HUNT_RUN_LABELS: Record<string, string> = {
  'Hunt analyst feedback': 'hunt_analyst_feedback',
  'Hunt run status': 'hunt_run_status',
  'Hunt run trigger': 'hunt_run_trigger',
};

describe('Hunt run attribute names', () => {
  it('should register the hunt run feedback, status and trigger under their own names', () => {
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, 'hunt_analyst_feedback')).toMatchObject({ type: 'string', label: 'Hunt analyst feedback' });
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, 'hunt_run_status')).toMatchObject({ label: 'Hunt run status' });
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, 'hunt_run_trigger')).toMatchObject({ label: 'Hunt run trigger' });
  });

  it('should not register the generic names other modules use', () => {
    ['analyst_feedback', 'run_status', 'run_trigger', 'evidence'].forEach((name) => {
      expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_HUNT_RUN, name)).toBeUndefined();
    });
  });

  it.each(Object.entries(HUNT_RUN_LABELS))('should give the label %s to the %s attribute only', (label, name) => {
    const names = schemaAttributesDefinition.getAllAttributes().filter((attribute) => attribute.label === label).map((attribute) => attribute.name);
    expect(names.filter((attributeName) => attributeName !== name)).toEqual([]);
  });
});
