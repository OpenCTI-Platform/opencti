import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import { transformCustomFieldValueAddInput, validateCustomFieldValues } from '../../../../src/modules/customField/custom-field-validator';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from '../../../../src/modules/customField/custom-field-types';
import type { CustomFieldValueAddInput } from '../../../../src/generated/graphql';

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

  it('throws on an unknown field_type on the definition', async () => {
    seed(makeDefinition({ field_type: 'unsupported' as any }));
    const values: CustomFieldValue[] = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'a' }];
    await expect(validate(values)).rejects.toThrow('Unknown custom field type');
  });
});

describe('transformCustomFieldValueAddInput', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const transform = (input: CustomFieldValueAddInput[]) => transformCustomFieldValueAddInput(CONTEXT, USER, input, ENTITY_TYPE);

  it('returns an empty array when no custom field definitions exist for the entity type', async () => {
    seed();
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['a'] } as any]);
    expect(result).toEqual([]);
  });

  it('drops an input whose field_name does not match any definition (nor an alias)', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', aliases: ['x_opencti_cf_alias'] } as any));
    const result = await transform([{ field_name: 'x_opencti_cf_unknown', value: ['a'] } as any]);
    expect(result).toEqual([]);
  });

  it('matches a definition through one of its aliases', async () => {
    seed(makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'string', aliases: ['x_opencti_cf_alias'] } as any));
    const result = await transform([{ field_name: 'x_opencti_cf_alias', value: ['hello'] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }]);
  });

  it('transforms an integer input', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'integer' }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: [42] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 42 }]);
  });

  it('transforms a markdown input using the string_value channel', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'markdown' }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['# Title'] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: '# Title' }]);
  });

  it('transforms a boolean input', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'boolean' }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: [true] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: true }]);
  });

  it('transforms a date input', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'date' }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['2026-01-01T00:00:00.000Z'] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', date_value: '2026-01-01T00:00:00.000Z' }]);
  });

  it('transforms a select input', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'select', select_options: ['a', 'b'] }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['a'] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_value: 'a' }]);
  });

  it('transforms a multi_select input, keeping the whole array', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'multi_select', select_options: ['a', 'b'] }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['a', 'b'] } as any]);
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['a', 'b'] }]);
  });

  it('drops an input whose value type does not match the definition (e.g. string for an integer field)', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'integer' }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['not-a-number'] } as any]);
    expect(result).toEqual([]);
  });

  it('drops a multi_select input containing a non-string value', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'multi_select', select_options: ['a', 'b'] }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: ['a', 42] } as any]);
    expect(result).toEqual([]);
  });

  it('drops an input with more than one value for a single-valued type (e.g. integer)', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'integer' }));
    const result = await transform([{ field_name: 'x_opencti_cf_field', value: [1, 2] } as any]);
    expect(result).toEqual([]);
  });

  it('throws on an unknown field_type on the matched definition', async () => {
    seed(makeDefinition({ id: 'cf-id-1', field_type: 'unsupported' as any }));
    await expect(transform([{ field_name: 'x_opencti_cf_field', value: ['a'] } as any])).rejects.toThrow('Unknown custom field type');
  });

  it('processes multiple inputs, mixing valid, dropped and alias-matched entries', async () => {
    seed(
      makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_score', field_type: 'integer' }),
      makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_label', field_type: 'string' }),
    );
    const result = await transform([
      { field_name: 'x_opencti_cf_score', value: [7] } as any,
      { field_name: 'x_opencti_cf_label', value: ['test'] } as any,
      { field_name: 'x_opencti_cf_missing', value: ['ignored'] } as any,
    ]);
    expect(result).toEqual([
      { field_id: 'cf-1', field_name: 'x_opencti_cf_score', int_value: 7 },
      { field_id: 'cf-2', field_name: 'x_opencti_cf_label', string_value: 'test' },
    ]);
  });
});
