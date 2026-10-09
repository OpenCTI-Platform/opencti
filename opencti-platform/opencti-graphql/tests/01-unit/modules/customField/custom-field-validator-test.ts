import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as cacheModule from '../../../../src/database/cache';
import {
  extractStringifiedCustomFieldValueFromStoreEntity,
  fillCustomFieldsDefaultValues,
  getCustomFieldDefaultValueFromEntitySettings,
  transformCustomFieldValueAddInput,
  validateCustomFieldValues,
  validateCustomFieldValuesEditInput,
} from '../../../../src/modules/customField/custom-field-validator';
import type { BasicStoreEntityCustomFieldDefinition, CustomFieldValue } from '../../../../src/modules/customField/custom-field-types';
import type { CustomFieldValueAddInput, EditInput } from '../../../../src/generated/graphql';
import { EditOperation } from '../../../../src/generated/graphql';

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
describe('validateCustomFieldValuesEditInput', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });
  const editInput = (value: any[], operation?: EditOperation): EditInput => ({ key: 'custom_field_values', value, operation } as EditInput);
  describe('replace (default) operation', () => {
    it('validates the input values as the full resulting set (delegates to validateCustomFieldValues)', async () => {
      seed(makeDefinition({ field_type: 'integer', min_value: 0, max_value: 10 }));
      const currentEntity = { entity_type: ENTITY_TYPE, custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 5 }] };
      const input = editInput([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 99 }], EditOperation.Replace);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).rejects.toThrow('int_value is above maximum');
    });
  });
  describe('remove operation', () => {
    it('throws when trying to remove a mandatory custom field value', async () => {
      seed(makeDefinition({
        field_type: 'string',
        entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: true }],
      }));
      const currentEntity = { entity_type: ENTITY_TYPE, custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }] };
      const input = editInput([{ field_id: 'cf-id-1' }], EditOperation.Remove);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).rejects.toThrow('Cannot remove mandatory custom field value');
    });
    it('does not throw when removing a non-mandatory custom field value', async () => {
      seed(makeDefinition({ field_type: 'string' }));
      const currentEntity = { entity_type: ENTITY_TYPE, custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }] };
      const input = editInput([{ field_id: 'cf-id-1' }], EditOperation.Remove);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).resolves.not.toThrow();
    });
  });
  describe('add operation', () => {
    it('merges (does not duplicate-error) select_values into an existing multi_select entry sharing the same field_id', async () => {
      seed(makeDefinition({ field_type: 'multi_select', select_options: ['alpha', 'bravo', 'charlie'] }));
      const currentEntity = {
        entity_type: ENTITY_TYPE,
        custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['alpha'] }],
      };
      const input = editInput([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['bravo'] }], EditOperation.Add);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).resolves.not.toThrow();
    });
    it('still throws when the SAME field_name is duplicated within the add input itself', async () => {
      seed(makeDefinition({ field_type: 'string' }));
      const currentEntity = { entity_type: ENTITY_TYPE, custom_field_values: [] };
      const input = editInput([
        { field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'a' },
        { field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'b' },
      ], EditOperation.Add);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).rejects.toThrow('Duplicate custom field entries found');
    });
    it('replaces (last-write-wins) an existing scalar value on add without throwing a duplicate error', async () => {
      seed(makeDefinition({ field_type: 'integer', min_value: 0, max_value: 100 }));
      const currentEntity = {
        entity_type: ENTITY_TYPE,
        custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 5 }],
      };
      const input = editInput([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 9 }], EditOperation.Add);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).resolves.not.toThrow();
    });
    it('still validates the merged value against its definition (e.g. rejects an out-of-range merge)', async () => {
      seed(makeDefinition({ field_type: 'integer', min_value: 0, max_value: 10 }));
      const currentEntity = {
        entity_type: ENTITY_TYPE,
        custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 5 }],
      };
      const input = editInput([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 999 }], EditOperation.Add);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).rejects.toThrow('int_value is above maximum');
    });
    it('leaves unrelated existing custom field values untouched alongside the new addition', async () => {
      seed(
        makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_a', field_type: 'string' }),
        makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_b', field_type: 'string' }),
      );
      const currentEntity = {
        entity_type: ENTITY_TYPE,
        custom_field_values: [{ field_id: 'cf-1', field_name: 'x_opencti_cf_a', string_value: 'kept' }],
      };
      const input = editInput([{ field_id: 'cf-2', field_name: 'x_opencti_cf_b', string_value: 'added' }], EditOperation.Add);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).resolves.not.toThrow();
    });
    it('handles adding to an entity that has no custom_field_values yet', async () => {
      seed(makeDefinition({ field_type: 'multi_select', select_options: ['alpha', 'bravo'] }));
      const currentEntity = { entity_type: ENTITY_TYPE, custom_field_values: undefined };
      const input = editInput([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['alpha'] }], EditOperation.Add);
      await expect(validateCustomFieldValuesEditInput(CONTEXT, USER, input, currentEntity)).resolves.not.toThrow();
    });
  });
});

describe('getCustomFieldDefaultValueFromEntitySettings', () => {
  const settingsFor = (default_value?: string, entityType = ENTITY_TYPE) => [{ entity_type: entityType, mandatory: false, default_value }];

  it('returns undefined when the definition has no setting for this entity type', () => {
    const definition = makeDefinition({ field_type: 'string', entity_type_settings: settingsFor('hello', 'Report') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toBeUndefined();
  });

  it('returns undefined when entity_type_settings is empty', () => {
    const definition = makeDefinition({ field_type: 'string', entity_type_settings: [] });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toBeUndefined();
  });

  it('returns undefined when the matching setting has no default_value configured', () => {
    const definition = makeDefinition({ field_type: 'string', entity_type_settings: settingsFor(undefined) });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toBeUndefined();
  });

  it('returns undefined when default_value is an empty string', () => {
    const definition = makeDefinition({ field_type: 'string', entity_type_settings: settingsFor('') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toBeUndefined();
  });

  it('builds an integer default value, parsing the string default_value into a number', () => {
    const definition = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'integer', entity_type_settings: settingsFor('5') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 5 });
  });

  it('builds a string default value', () => {
    const definition = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'string', entity_type_settings: settingsFor('hello') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' });
  });

  it('builds a markdown default value using the same string_value channel', () => {
    const definition = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'markdown', entity_type_settings: settingsFor('# Title') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: '# Title' });
  });

  it('builds a select default value', () => {
    const definition = makeDefinition({
      id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'select', select_options: ['a', 'b'], entity_type_settings: settingsFor('a'),
    });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_value: 'a' });
  });

  it('builds a date default value', () => {
    const definition = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'date', entity_type_settings: settingsFor('2026-01-01T00:00:00.000Z') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', date_value: '2026-01-01T00:00:00.000Z' });
  });

  it('builds a multi_select default value, wrapping the single default_value into an array', () => {
    const definition = makeDefinition({
      id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'multi_select', select_options: ['a', 'b'], entity_type_settings: settingsFor('a'),
    });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['a'] });
  });

  it('builds a boolean default value of true, case-insensitively', () => {
    const definition = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'boolean', entity_type_settings: settingsFor('TRUE') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: true });
  });

  it('builds a boolean default value of false for any non-"true" string', () => {
    const definition = makeDefinition({ id: 'cf-id-1', name: 'x_opencti_cf_field', field_type: 'boolean', entity_type_settings: settingsFor('no') });
    expect(getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toEqual({ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: false });
  });

  it('throws on an unknown field_type when a default_value is configured', () => {
    const definition = makeDefinition({ field_type: 'unsupported' as any, entity_type_settings: settingsFor('x') });
    expect(() => getCustomFieldDefaultValueFromEntitySettings(definition, ENTITY_TYPE)).toThrow('Unknown custom field type');
  });
});

describe('fillCustomFieldsDefaultValues', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const fill = (recordInput: Record<string, any>) => fillCustomFieldsDefaultValues(CONTEXT, USER, recordInput, ENTITY_TYPE);

  it('returns undefined when there are no custom field definitions for the entity type and no pre-existing values', async () => {
    seed();
    expect(await fill({})).toBeUndefined();
  });

  it('returns undefined when the definition is not configured (no entity_type_settings) for this entity type', async () => {
    seed(makeDefinition({ field_type: 'string', entity_type_settings: [] }));
    expect(await fill({})).toBeUndefined();
  });

  it('does not add a default value for a configured field that has no default_value set', async () => {
    seed(makeDefinition({ field_type: 'string', entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false }] }));
    expect(await fill({})).toBeUndefined();
  });

  // Covers the getCustomFieldDefaultValueFromEntitySettings call and the push of the resulting
  // default value (lines 168-170 of fillCustomFieldsDefaultValues).
  it('computes and pushes the default value for a configured field with a default_value that is not already set', async () => {
    seed(makeDefinition({
      id: 'cf-id-1',
      name: 'x_opencti_cf_field',
      field_type: 'integer',
      entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false, default_value: '5' }],
    }));
    const result = await fill({});
    expect(result).toEqual([{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 5 }]);
  });

  it('does not override a value already provided for the same field', async () => {
    seed(makeDefinition({
      id: 'cf-id-1',
      name: 'x_opencti_cf_field',
      field_type: 'integer',
      entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false, default_value: '5' }],
    }));
    const existing = [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 42 }];
    const result = await fill({ custom_field_values: existing });
    expect(result).toEqual(existing);
  });

  it('keeps an existing empty custom_field_values array when no default value applies', async () => {
    seed(makeDefinition({ field_type: 'string', entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false }] }));
    const result = await fill({ custom_field_values: [] });
    expect(result).toEqual([]);
  });

  it('fills defaults for multiple fields independently, only pushing the ones with a default_value', async () => {
    seed(
      makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_a', field_type: 'string', entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false, default_value: 'hello' }] }),
      makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_b', field_type: 'string', entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false }] }),
    );
    const result = await fill({});
    expect(result).toEqual([{ field_id: 'cf-1', field_name: 'x_opencti_cf_a', string_value: 'hello' }]);
  });
});

describe('extractStringifiedCustomFieldValueFromStoreEntity', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const extract = (element: Record<string, any>, fieldName: string) => extractStringifiedCustomFieldValueFromStoreEntity(CONTEXT, USER, element, fieldName);

  it('returns undefined when no custom field definition matches the given name', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_other' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_other', string_value: 'hello' }] };
    const result = await extract(element, 'x_opencti_cf_unknown');
    expect(result).toBeUndefined();
  });

  it('resolves the definition through one of its aliases', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string', aliases: ['x_opencti_cf_alias'] } as any));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello' }] };
    const result = await extract(element, 'x_opencti_cf_alias');
    expect(result).toBe('hello');
  });

  it('returns undefined when the element has no custom field value matching the definition', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string' }));
    const element = { custom_field_values: [{ field_id: 'other-id', field_name: 'x_opencti_cf_other', string_value: 'hello' }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBeUndefined();
  });

  it('returns undefined when the element has no custom_field_values at all', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string' }));
    const result = await extract({}, 'x_opencti_cf_field');
    expect(result).toBeUndefined();
  });

  it('stringifies an integer value', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'integer' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', int_value: 42 }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('42');
  });

  it('returns a string value as-is', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'hello world' }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('hello world');
  });

  it('returns a markdown value using the same string_value channel', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'markdown' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: '# Title' }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('# Title');
  });

  it('stringifies a true boolean value', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'boolean' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: true }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('true');
  });

  it('stringifies a false boolean value (not treated as empty)', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'boolean' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', boolean_value: false }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('false');
  });

  it('stringifies a date value', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'date' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', date_value: '2026-01-01T00:00:00.000Z' }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('2026-01-01T00:00:00.000Z');
  });

  it('returns a select value as-is', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'select', select_options: ['a', 'b'] }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_value: 'b' }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('b');
  });

  it('joins multi_select values with a comma', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'multi_select', select_options: ['a', 'b', 'c'] }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: ['a', 'c'] }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('a,c');
  });

  it('returns an empty string when multi_select value is an empty array', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'multi_select', select_options: ['a', 'b'] }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', select_values: [] }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBe('');
  });

  it('returns undefined when the relevant value field is empty (e.g. missing string_value)', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'string' }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field' }] };
    const result = await extract(element, 'x_opencti_cf_field');
    expect(result).toBeUndefined();
  });

  it('throws on an unknown field_type on the matched definition', async () => {
    seed(makeDefinition({ name: 'x_opencti_cf_field', field_type: 'unsupported' as any }));
    const element = { custom_field_values: [{ field_id: 'cf-id-1', field_name: 'x_opencti_cf_field', string_value: 'a' }] };
    await expect(extract(element, 'x_opencti_cf_field')).rejects.toThrow('Unknown custom field type');
  });
});
