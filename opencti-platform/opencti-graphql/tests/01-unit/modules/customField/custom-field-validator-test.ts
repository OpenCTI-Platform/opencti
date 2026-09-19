import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import { validateCustomFieldValues } from '../../../../src/modules/customField/custom-field-validator';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from '../../../../src/modules/customField/custom-field-types';

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;
const ENTITY_TYPE = 'Case-Incident';

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  standard_id: 'custom-field-definition--id-1',
  entity_type: 'CustomFieldDefinition',
  name: 'x_opencti_cf_field',
  label: 'Field',
  description: '',
  field_type: 'string',
  entity_types: [ENTITY_TYPE],
  entity_type_settings: [],
  multiple: false,
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

const seed = (...definitions: BasicStoreEntityCustomFieldDefinition[]) => {
  vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(definitions);
};

const validate = (values: CustomFieldValue[]) => validateCustomFieldValues(CONTEXT, USER, values, ENTITY_TYPE);

describe('validateCustomFieldValues', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('does nothing when there are no definitions and no values', async () => {
    seed();
    await expect(validate([])).resolves.not.toThrow();
  });

  it('throws when values are provided but no definitions exist for the entity type', async () => {
    seed();
    const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }];
    await expect(validate(values)).rejects.toThrow('No custom field definitions found for entity type');
  });

  it('throws on duplicate field_name entries', async () => {
    seed(makeDefinition({ field_type: 'string' }));
    const values: CustomFieldValue[] = [
      { field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'a' },
      { field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'b' },
    ];
    await expect(validate(values)).rejects.toThrow('Duplicate custom field entries found');
  });

  it('throws when a value references a field_name with no matching definition', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field' }));
    const values: CustomFieldValue[] = [{ field_id: 'unknown', field_name: 'x_opencti_cf_unknown', string_value: 'a' }];
    await expect(validate(values)).rejects.toThrow('Custom field definition not found for this entity type');
  });

  describe('integer fields', () => {
    it('throws when int_value is missing', async () => {
      seed(makeDefinition({ field_type: 'integer' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }];
      await expect(validate(values)).rejects.toThrow('int_value is required');
    });

    it('throws when int_value is not an integer', async () => {
      seed(makeDefinition({ field_type: 'integer' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 4.2 }];
      await expect(validate(values)).rejects.toThrow('int_value must be an integer');
    });

    it('throws when int_value is below min_value', async () => {
      seed(makeDefinition({ field_type: 'integer', min_value: 10 }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 5 }];
      await expect(validate(values)).rejects.toThrow('int_value is below minimum');
    });

    it('throws when int_value is above max_value', async () => {
      seed(makeDefinition({ field_type: 'integer', max_value: 10 }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 15 }];
      await expect(validate(values)).rejects.toThrow('int_value is above maximum');
    });

    it('accepts a valid integer within bounds, including zero', async () => {
      seed(makeDefinition({ field_type: 'integer', min_value: 0, max_value: 100 }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 0 }];
      await expect(validate(values)).resolves.not.toThrow();
    });
  });

  describe('string / markdown fields', () => {
    it('throws when string_value is missing', async () => {
      seed(makeDefinition({ field_type: 'string' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }];
      await expect(validate(values)).rejects.toThrow('string_value is required');
    });

    it('accepts a valid string value', async () => {
      seed(makeDefinition({ field_type: 'string' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }];
      await expect(validate(values)).resolves.not.toThrow();
    });

    it('accepts a valid markdown value using the same string_value channel', async () => {
      seed(makeDefinition({ field_type: 'markdown' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: '# Title' }];
      await expect(validate(values)).resolves.not.toThrow();
    });
  });

  describe('boolean fields', () => {
    it('throws when boolean_value is missing', async () => {
      seed(makeDefinition({ field_type: 'boolean' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }];
      await expect(validate(values)).rejects.toThrow('boolean_value is required');
    });

    it('accepts false as a valid value (not treated as missing)', async () => {
      seed(makeDefinition({ field_type: 'boolean' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: false }];
      await expect(validate(values)).resolves.not.toThrow();
    });

    it('accepts true as a valid value', async () => {
      seed(makeDefinition({ field_type: 'boolean' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: true }];
      await expect(validate(values)).resolves.not.toThrow();
    });
  });

  describe('date fields', () => {
    it('throws when date_value is missing', async () => {
      seed(makeDefinition({ field_type: 'date' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }];
      await expect(validate(values)).rejects.toThrow('date_value is required');
    });

    it('throws when date_value is not a valid date', async () => {
      seed(makeDefinition({ field_type: 'date' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', date_value: 'not-a-date' }];
      await expect(validate(values)).rejects.toThrow('date_value must be a valid ISO date string');
    });

    it('accepts a valid ISO date', async () => {
      seed(makeDefinition({ field_type: 'date' }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', date_value: '2026-01-01T00:00:00.000Z' }];
      await expect(validate(values)).resolves.not.toThrow();
    });
  });

  describe('select fields', () => {
    it('throws when select_value is missing', async () => {
      seed(makeDefinition({ field_type: 'select', select_options: ['a', 'b'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }];
      await expect(validate(values)).rejects.toThrow('select_value is required');
    });

    it('throws when the definition has no select_options configured', async () => {
      seed(makeDefinition({ field_type: 'select', select_options: [] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_value: 'a' }];
      await expect(validate(values)).rejects.toThrow('No select_options configured');
    });

    it('throws when select_value is not in the allowed options', async () => {
      seed(makeDefinition({ field_type: 'select', select_options: ['a', 'b'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_value: 'c' }];
      await expect(validate(values)).rejects.toThrow('select_value is not in the allowed options');
    });

    it('accepts a select_value present in the allowed options', async () => {
      seed(makeDefinition({ field_type: 'select', select_options: ['a', 'b'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_value: 'b' }];
      await expect(validate(values)).resolves.not.toThrow();
    });
  });

  describe('multi_select fields', () => {
    it('throws when select_values is missing', async () => {
      seed(makeDefinition({ field_type: 'multi_select', select_options: ['a', 'b'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }];
      await expect(validate(values)).rejects.toThrow('select_values is required');
    });

    it('throws when select_values is not an array', async () => {
      seed(makeDefinition({ field_type: 'multi_select', select_options: ['a', 'b'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: 'a' as unknown as string[] }];
      await expect(validate(values)).rejects.toThrow('select_values must be an array');
    });

    it('throws when select_values contains a value outside the allowed options', async () => {
      seed(makeDefinition({ field_type: 'multi_select', select_options: ['a', 'b'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['a', 'c'] }];
      await expect(validate(values)).rejects.toThrow('select_values contains values that are not in the allowed options');
    });

    it('accepts select_values fully included in the allowed options', async () => {
      seed(makeDefinition({ field_type: 'multi_select', select_options: ['a', 'b', 'c'] }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['a', 'c'] }];
      await expect(validate(values)).resolves.not.toThrow();
    });
  });

  describe('mandatory enforcement', () => {
    it('throws when a mandatory field for this entity type is not provided at all', async () => {
      seed(makeDefinition({
        field_type: 'string',
        entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: true }],
      }));
      await expect(validate([])).rejects.toThrow('Mandatory custom field is missing');
    });

    it('does not throw when the mandatory field is provided', async () => {
      seed(makeDefinition({
        field_type: 'string',
        entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: true }],
      }));
      const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }];
      await expect(validate(values)).resolves.not.toThrow();
    });

    it('does not enforce mandatory when the setting applies to a different entity type', async () => {
      seed(makeDefinition({
        field_type: 'string',
        entity_type_settings: [{ entity_type: 'Report', mandatory: true }],
      }));
      await expect(validate([])).resolves.not.toThrow();
    });
  });
});
