import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  buildCustomFieldValueAddInputEntry,
  buildCustomFieldValueEntry,
  buildCustomFieldValuesAddInput,
  buildCustomFieldsValidationSchema,
  CustomFieldDef,
  CustomFieldStoredValue,
  CustomFieldValue,
  getCustomFieldCurrentValue,
  getCustomFieldDisplayValue,
  getCustomFieldLabel,
  getCustomFieldsInitialValues,
  getCustomFieldSetting,
  getCustomFieldValueError,
  getCustomFieldValues,
  isCustomFieldValueSet,
  updateCustomFieldValues,
} from './customFields';

const definition = (fieldType: string, overrides: Partial<CustomFieldDef> = {}): CustomFieldDef => ({
  id: fieldType,
  name: `custom_${fieldType}`,
  label: `Custom ${fieldType}`,
  field_type: fieldType,
  min_value: null,
  max_value: null,
  select_options: null,
  entity_type_settings: null,
  ...overrides,
});

const translate = (key: string) => key;

const valueCases: [string, CustomFieldValue, Partial<CustomFieldStoredValue>][] = [
  ['string', 'text', { string_value: 'text' }],
  ['markdown', '**text**', { string_value: '**text**' }],
  ['integer', '0', { int_value: 0 }],
  ['boolean', false, { boolean_value: false }],
  ['boolean', true, { boolean_value: true }],
  ['date', '2026-09-11T12:00:00.000Z', { date_value: '2026-09-11T12:00:00.000Z' }],
  ['select', 'option', { select_value: 'option' }],
  ['multi_select', ['one', 'two'], { select_values: ['one', 'two'] }],
];

describe('customFields', () => {
  afterEach(() => vi.useRealTimers());

  it.each(valueCases)('round-trips a %s UI value through its stored representation', (type, rawValue, storedValue) => {
    const def = definition(type);
    const entry = buildCustomFieldValueEntry(def, rawValue);
    expect(entry).toEqual({ field_id: def.id, field_name: def.name, ...storedValue });
    expect(getCustomFieldCurrentValue(def, [entry])).toEqual(rawValue);
  });

  it.each(valueCases)('serializes a %s creation value using its technical name', (type, rawValue, storedValue) => {
    const entry = buildCustomFieldValueAddInputEntry(definition(type), rawValue);
    expect(entry).toEqual({ field_name: `custom_${type}`, value: Object.values(storedValue).flat() });
  });

  it('builds creation inputs only for definitions with submitted values', () => {
    expect(buildCustomFieldValuesAddInput(
      [definition('string'), definition('integer'), definition('date')],
      { string: '', integer: '0', unknown: 'ignored' },
    )).toEqual([{ field_name: 'custom_integer', value: [0] }]);
    expect(buildCustomFieldValuesAddInput([], {})).toEqual([]);
  });

  it('preserves a mandatory false boolean alongside another populated custom field', () => {
    const boolean = definition('boolean', {
      entity_type_settings: [{ entity_type: 'Report', mandatory: true, default_value: 'true' }],
    });
    expect(buildCustomFieldValuesAddInput([boolean, definition('string')], { boolean: false, string: 'text' })).toEqual([
      { field_name: 'custom_boolean', value: [false] },
      { field_name: 'custom_string', value: ['text'] },
    ]);
  });

  it('forwards only serialized custom-field inputs to explicit and bulk creation builders', () => {
    const customFieldValues = [{ field_name: 'custom_string', value: ['text'] }];
    const values = { name: 'Campaign', customFieldValues };
    expect(getCustomFieldValues(values)).toEqual({ customFieldValues });
    expect(getCustomFieldValues({ name: 'Campaign', customFields: { string: 'raw' } })).toEqual({});
    expect(['one', 'two'].map((name) => ({ name, ...getCustomFieldValues(values) }))).toEqual([
      { name: 'one', customFieldValues }, { name: 'two', customFieldValues },
    ]);
  });

  it.each([
    ['string', ''],
    ['integer', ''],
    ['boolean', false],
    ['multi_select', []],
  ])('reads an empty %s field without applying configured defaults', (type, expected) => {
    expect(getCustomFieldCurrentValue(definition(type as string), [])).toEqual(expected);
  });

  it('copies multi-select values read from Relay data', () => {
    const selected = Object.freeze(['one']);
    const entry = { field_id: 'multi_select', field_name: 'custom_multi_select', select_values: selected };
    const result = getCustomFieldCurrentValue(definition('multi_select'), [entry]);
    expect(result).toEqual(selected);
    expect(result).not.toBe(selected);
  });

  it('resolves per-entity defaults and resolves @now only for dates', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-09-11T12:00:00.000Z'));
    const defaults = { boolean: 'true', multi_select: 'one', integer: '0', date: '@now', string: '@now' };
    const definitions = Object.entries(defaults).map(([type, defaultValue]) => definition(type, {
      entity_type_settings: [
        { entity_type: 'Case-Incident', mandatory: false, default_value: 'other' },
        { entity_type: 'Report', mandatory: true, default_value: defaultValue },
      ],
    }));
    expect(getCustomFieldsInitialValues(definitions, 'Report')).toEqual({
      boolean: true, multi_select: ['one'], integer: '0', date: '2026-09-11T12:00:00.000Z', string: '@now',
    });
    expect(getCustomFieldsInitialValues(definitions, 'Malware')).toEqual({
      boolean: false, multi_select: [], integer: '', date: '', string: '',
    });
    expect(getCustomFieldSetting(definitions[0], 'Report')?.mandatory).toBe(true);
    expect(getCustomFieldSetting(definitions[0], 'Malware')).toBeUndefined();
    expect(getCustomFieldsInitialValues([], 'Report')).toEqual({});
  });

  it.each(['string', 'integer', 'date', 'select', 'markdown', 'multi_select'])('validates mandatory %s values for the selected entity type', (type) => {
    const def = definition(type, {
      entity_type_settings: [{ entity_type: 'Report', mandatory: true, default_value: null }],
    });
    const emptyValue = type === 'multi_select' ? [] : '';
    const schema = buildCustomFieldsValidationSchema([def], 'Report', translate);
    expect(() => schema.validateSync({ [def.id]: emptyValue })).toThrow('This field is required');
    expect(schema.isValidSync({ [def.id]: type === 'multi_select' ? ['one'] : '1' })).toBe(true);
    expect(buildCustomFieldsValidationSchema([def], 'Malware', translate).isValidSync({ [def.id]: emptyValue })).toBe(true);
  });

  it('allows false for a mandatory boolean', () => {
    const def = definition('boolean', {
      entity_type_settings: [{ entity_type: 'Report', mandatory: true, default_value: null }],
    });
    expect(buildCustomFieldsValidationSchema([def], 'Report', translate).isValidSync({ boolean: false })).toBe(true);
  });

  it('keeps an optional integer optional', () => {
    const schema = buildCustomFieldsValidationSchema([definition('integer')], 'Report', translate);
    expect(schema.isValidSync({ integer: '' })).toBe(true);
    expect(schema.isValidSync({ integer: '42' })).toBe(true);
  });

  it.each(['1.9', 'abc'])('rejects an integer value that is not an integer (%s)', (rawValue) => {
    const schema = buildCustomFieldsValidationSchema([definition('integer')], 'Report', translate);
    expect(() => schema.validateSync({ integer: rawValue })).toThrow('The value must be an integer');
  });

  it.each(['-1', '101'])('rejects an integer value outside the min/max bounds (%s)', (rawValue) => {
    const schema = buildCustomFieldsValidationSchema([definition('integer', { min_value: 0, max_value: 100 })], 'Report', translate);
    expect(() => schema.validateSync({ integer: rawValue })).toThrow('The value must be between min and max value');
    expect(schema.isValidSync({ integer: '100' })).toBe(true);
  });

  it('converts integers without truncating them', () => {
    expect(buildCustomFieldValueAddInputEntry(definition('integer'), '1e3')).toEqual({ field_name: 'custom_integer', value: [1000] });
    expect(buildCustomFieldValueAddInputEntry(definition('integer'), '1.9')).toEqual({ field_name: 'custom_integer', value: [1.9] });
  });

  it('reports integer errors with the same rules as the creation schema', () => {
    const bounded = definition('integer', { min_value: 0, max_value: 100 });
    expect(getCustomFieldValueError(bounded, '', translate)).toBeUndefined();
    expect(getCustomFieldValueError(bounded, '42', translate)).toBeUndefined();
    expect(getCustomFieldValueError(bounded, '1.9', translate)).toBe('The value must be an integer');
    expect(getCustomFieldValueError(bounded, 'abc', translate)).toBe('The value must be an integer');
    expect(getCustomFieldValueError(bounded, '101', translate)).toBe('The value must be between min and max value');
    expect(getCustomFieldValueError(definition('string'), '1.9', translate)).toBeUndefined();
  });

  it('bounds integers without min/max to the 32-bit range', () => {
    const unbounded = definition('integer');
    expect(getCustomFieldValueError(unbounded, '2147483647', translate)).toBeUndefined();
    expect(getCustomFieldValueError(unbounded, '3000000000', translate)).toBe('The value must be between min and max value');
    const schema = buildCustomFieldsValidationSchema([unbounded], 'Report', translate);
    expect(schema.isValidSync({ integer: '-2147483648' })).toBe(true);
    expect(() => schema.validateSync({ integer: '3000000000' })).toThrow('The value must be between min and max value');
  });

  it('clears an integer value when the input is emptied', () => {
    const stored = Object.freeze([{ field_id: 'integer', field_name: 'custom_integer', int_value: 5 }]);
    expect(updateCustomFieldValues(definition('integer'), '', stored)).toEqual([]);
  });

  it.each(valueCases)('updates a %s value without changing unrelated stored fields', (type, rawValue, storedValue) => {
    const other = Object.freeze({ field_id: 'other', field_name: 'other', string_value: 'keep' });
    const old = Object.freeze({ field_id: type, field_name: `custom_${type}`, string_value: 'old' });
    const values = Object.freeze([old, other]);
    expect(updateCustomFieldValues(definition(type), rawValue, values)).toEqual([
      other, { field_id: type, field_name: `custom_${type}`, ...storedValue },
    ]);
    expect(values).toEqual([old, other]);
  });

  it.each<[string, CustomFieldValue]>([
    ['string', ''], ['integer', ''], ['integer', 'invalid'], ['date', ''], ['select', ''], ['multi_select', []],
  ])('removes a cleared or invalid %s value', (type, rawValue) => {
    const other = { field_id: 'other', field_name: 'other', int_value: 1 };
    expect(updateCustomFieldValues(definition(type), rawValue, [
      other, { field_id: type, field_name: `custom_${type}` },
    ])).toEqual([other]);
  });

  it('adds a previously unset field and preserves false and zero as set values', () => {
    expect(updateCustomFieldValues(definition('boolean'), false, [])).toEqual([
      { field_id: 'boolean', field_name: 'custom_boolean', boolean_value: false },
    ]);
    expect(isCustomFieldValueSet(false)).toBe(true);
    expect(isCustomFieldValueSet(0)).toBe(true);
    expect(isCustomFieldValueSet([])).toBe(false);
    expect(isCustomFieldValueSet(undefined)).toBe(false);
  });

  it('uses definition labels with a readable technical-name fallback', () => {
    const value = { field_id: 'risk', field_name: 'risk_score' };
    expect(getCustomFieldLabel(value, [definition('integer', { id: 'risk', label: 'Risk assessment' })])).toBe('Risk assessment');
    expect(getCustomFieldLabel(value, [])).toBe('Risk score');
  });

  it.each<[Partial<CustomFieldStoredValue>, string]>([
    [{ boolean_value: false }, 'translated:False'],
    [{ boolean_value: true }, 'translated:True'],
    [{ date_value: '2026-09-11' }, 'date:2026-09-11'],
    [{ int_value: 0 }, '0'],
    [{ select_values: ['one', 'two'] }, 'one, two'],
    [{ select_value: 'one' }, 'one'],
    [{ string_value: '**text**' }, '**text**'],
    [{ select_values: [], string_value: null }, ''],
    [{}, ''],
  ])('formats stored values for display: %j', (storedValue, expected) => {
    expect(getCustomFieldDisplayValue({ field_id: 'id', field_name: 'name', ...storedValue }, {
      t_i18n: (key) => `translated:${key}`,
      fldt: (date) => `date:${date}`,
    })).toBe(expected);
  });
});
