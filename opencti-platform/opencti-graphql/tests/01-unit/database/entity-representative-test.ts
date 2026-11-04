import { describe, expect, it } from 'vitest';
import { extractEntityRepresentativeName } from '../../../src/database/entity-representative';
import { ENTITY_TYPE_CUSTOM_FIELD_DEFINITION } from '../../../src/modules/customField/custom-field-types';

describe('extractEntityRepresentativeName', () => {
  it('should use the label of a custom field definition', () => {
    const definition = { entity_type: ENTITY_TYPE_CUSTOM_FIELD_DEFINITION, name: 'x_opencti_cf_note', label: 'Analyst note' };
    expect(extractEntityRepresentativeName(definition)).toEqual('Analyst note');
  });
});
