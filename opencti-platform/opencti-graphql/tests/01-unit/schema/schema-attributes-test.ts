import { describe, expect, it, vi } from 'vitest';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { ENTITY_TYPE_GROUP, ENTITY_TYPE_USER } from '../../../src/schema/internalObject';
import type { AttributeDefinition, ComplexAttributeWithMappings, MappingDefinition } from '../../../src/schema/attribute-definition';

// Test configuration enables all feature flags, keep one disabled to check flagged attributes are ignored
const DISABLED_FEATURE_FLAG = 'TEST_DISABLED_FEATURE_FLAG';
const ENABLED_FEATURE_FLAG = 'TEST_ENABLED_FEATURE_FLAG';
vi.mock('../../../src/config/conf', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/config/conf')>()),
  isFeatureEnabled: (feature: string) => feature !== DISABLED_FEATURE_FLAG,
}));

const base = { multiple: false, mandatoryType: 'no', upsert: false, isFilterable: false, editDefault: false } as const;
const short = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'string', format: 'short' });
const text = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'string', format: 'text' });
const integer = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'numeric', precision: 'integer' });
const float = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'numeric', precision: 'float' });
const json = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'string', format: 'json', multiple: false });
const date = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'date' });
const boolean = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'boolean' });
const flat = (name: string): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'object', format: 'flat' });
const standard = (name: string, mappings: MappingDefinition[]): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'object', format: 'standard', mappings });
const nested = (name: string, mappings: MappingDefinition[]): MappingDefinition => ({ ...base, name, label: `Test ${name}`, type: 'object', format: 'nested', mappings });

// Register the first attribute and return the registration of the second one, both having the same name on different entity types
const registerSameName = (existingAttribute: AttributeDefinition, attribute: AttributeDefinition) => {
  schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_USER, [existingAttribute]);
  return () => schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_GROUP, [attribute]);
};

const MAPPINGS_ERROR = 'You can\'t have two object attributes with the same name and different mappings in the platform';
const TYPE_ERROR = 'You can\'t have two attributes with the same name and a different type in the platform';
const STRING_FORMAT_ERROR = 'You can\'t have two string attributes with the same name and different format if the formats are not both short format';

describe('Schema attributes registration of attributes with the same name', () => {
  it('should accept attributes with the same storage', () => {
    expect(registerSameName(short('test_same_short'), short('test_same_short'))).not.toThrow();
    expect(registerSameName(text('test_same_text'), text('test_same_text'))).not.toThrow();
    expect(registerSameName(integer('test_same_integer'), integer('test_same_integer'))).not.toThrow();
    expect(registerSameName(date('test_same_date'), date('test_same_date'))).not.toThrow();
    expect(registerSameName(boolean('test_same_boolean'), boolean('test_same_boolean'))).not.toThrow();
    expect(registerSameName(flat('test_same_flat'), flat('test_same_flat'))).not.toThrow();
  });

  it('should accept short string formats as equivalent', () => {
    const idAttribute: AttributeDefinition = { ...base, name: 'test_short_id', label: 'Test test_short_id', type: 'string', format: 'id', entityTypes: [] };
    expect(registerSameName(short('test_short_id'), idAttribute)).not.toThrow();
  });

  it('should reject string attributes with different formats if not both short', () => {
    expect(registerSameName(short('test_short_text'), text('test_short_text'))).toThrow(STRING_FORMAT_ERROR);
    expect(registerSameName(text('test_text_json'), json('test_text_json'))).toThrow(STRING_FORMAT_ERROR);
  });

  it('should reject numeric attributes with different precisions', () => {
    expect(registerSameName(integer('test_numeric_precision'), float('test_numeric_precision'))).toThrow(TYPE_ERROR);
  });

  it('should reject attributes with different types', () => {
    expect(registerSameName(short('test_string_numeric'), integer('test_string_numeric'))).toThrow(TYPE_ERROR);
    expect(registerSameName(date('test_date_boolean'), boolean('test_date_boolean'))).toThrow(TYPE_ERROR);
    expect(registerSameName(boolean('test_boolean_string'), short('test_boolean_string'))).toThrow(TYPE_ERROR);
    expect(registerSameName(integer('test_numeric_object'), flat('test_numeric_object'))).toThrow(TYPE_ERROR);
  });

  it('should ignore string attributes under a disabled feature flag', () => {
    expect(registerSameName(short('test_ff_disabled'), { ...text('test_ff_disabled'), featureFlag: DISABLED_FEATURE_FLAG })).not.toThrow();
    expect(schemaAttributesDefinition.attributes[ENTITY_TYPE_GROUP].has('test_ff_disabled')).toBeFalsy();
    expect(registerSameName(short('test_ff_enabled'), { ...text('test_ff_enabled'), featureFlag: ENABLED_FEATURE_FLAG })).toThrow(STRING_FORMAT_ERROR);
  });

  it('should reject object attributes with different formats', () => {
    expect(registerSameName(flat('test_flat_standard'), standard('test_flat_standard', []))).toThrow(TYPE_ERROR);
    expect(registerSameName(standard('test_standard_nested', []), nested('test_standard_nested', []))).toThrow(TYPE_ERROR);
  });
});

describe.each([
  { format: 'standard', object: standard },
  { format: 'nested', object: nested },
])('Schema attributes registration of $format objects', ({ format, object }) => {
  const register = (name: string, existingMappings: MappingDefinition[], mappings: MappingDefinition[]) => {
    return registerSameName(object(`${format}_${name}`, existingMappings), object(`${format}_${name}`, mappings));
  };

  it('should accept objects with identical mappings', () => {
    const sub = nested('test_sub', [short('test_value')]);
    const registration = register('test_identical', [short('test_id'), integer('test_count'), sub], [integer('test_count'), sub, short('test_id')]);
    expect(registration).not.toThrow();
  });

  it('should accept short string formats as equivalent', () => {
    const idMapping: MappingDefinition = { ...base, name: 'test_id', label: 'Test test_id', type: 'string', format: 'id', entityTypes: [] };
    expect(register('test_short_formats', [short('test_id')], [idMapping])).not.toThrow();
  });

  it('should reject objects with missing or additional mappings', () => {
    expect(register('test_missing', [short('test_id'), short('test_name')], [short('test_id')])).toThrow(MAPPINGS_ERROR);
    expect(register('test_additional', [short('test_id')], [short('test_id'), short('test_name')])).toThrow(MAPPINGS_ERROR);
  });

  it('should reject objects with mappings of a different storage', () => {
    expect(register('test_string_format', [short('test_id')], [text('test_id')])).toThrow(STRING_FORMAT_ERROR);
    expect(register('test_type', [short('test_id')], [integer('test_id')])).toThrow(TYPE_ERROR);
    expect(register('test_precision', [integer('test_count')], [float('test_count')])).toThrow(TYPE_ERROR);
  });

  it('should ignore mappings under a disabled feature flag', () => {
    const disabledMapping = { ...short('test_name'), featureFlag: DISABLED_FEATURE_FLAG };
    expect(register('test_ff_disabled_mapping', [short('test_id')], [short('test_id'), disabledMapping])).not.toThrow();
    const enabledMapping = { ...short('test_name'), featureFlag: ENABLED_FEATURE_FLAG };
    expect(register('test_ff_enabled_mapping', [short('test_id')], [short('test_id'), enabledMapping])).toThrow(MAPPINGS_ERROR);
  });

  it('should ignore mappings under a disabled feature flag inside sub objects', () => {
    const sub = nested('test_sub', [short('test_value')]);
    const subWithDisabledMapping = nested('test_sub', [short('test_value'), { ...short('test_name'), featureFlag: DISABLED_FEATURE_FLAG }]);
    expect(register('test_ff_deep_disabled_last', [sub], [subWithDisabledMapping])).not.toThrow();
    expect(register('test_ff_deep_disabled_first', [subWithDisabledMapping], [sub])).not.toThrow();
    // Disabled mapping is not registered, so it's not part of the engine mapping
    const registered = schemaAttributesDefinition.attributes[ENTITY_TYPE_USER].get(`${format}_test_ff_deep_disabled_first`) as ComplexAttributeWithMappings;
    expect((registered.mappings[0] as ComplexAttributeWithMappings).mappings.map((m) => m.name)).toEqual(['test_value']);
    const subWithEnabledMapping = nested('test_sub', [short('test_value'), { ...short('test_name'), featureFlag: ENABLED_FEATURE_FLAG }]);
    expect(register('test_ff_deep_enabled', [sub], [subWithEnabledMapping])).toThrow(MAPPINGS_ERROR);
  });

  it('should reject objects with inconsistencies deep inside sub objects', () => {
    const missing = register('test_deep_missing', [nested('test_sub', [short('test_value')])], [nested('test_sub', [])]);
    expect(missing).toThrow(MAPPINGS_ERROR);
    const type = register('test_deep_type', [nested('test_sub', [short('test_value')])], [nested('test_sub', [integer('test_value')])]);
    expect(type).toThrow(TYPE_ERROR);
  });
});

describe('Schema attributes type of one attribute', () => {
  it('should answer as the check with several types', () => {
    schemaAttributesDefinition.registerAttributes(ENTITY_TYPE_USER, [
      date('test_type_date'),
      boolean('test_type_boolean'),
      integer('test_type_integer'),
      short('test_type_short'),
      standard('test_type_object', [integer('test_type_count'), date('test_type_seen')]),
      flat('test_type_flat'),
    ]);
    const names = ['test_type_date', 'test_type_boolean', 'test_type_integer', 'test_type_short', 'test_type_object.test_type_count',
      'test_type_object.test_type_seen', 'test_type_flat.anything', 'test_type_object.*', 'test_type_unknown'];
    for (const name of names) {
      for (const type of ['date', 'boolean', 'numeric'] as const) {
        expect(schemaAttributesDefinition.isTypeAttribute(name, type), `${name} ${type}`).toBe(schemaAttributesDefinition.isSpecificTypeAttribute(name, type));
      }
    }
    expect(schemaAttributesDefinition.isTypeAttribute('test_type_object.test_type_seen', 'date')).toBe(true);
    expect(schemaAttributesDefinition.isTypeAttribute('test_type_integer', 'numeric')).toBe(true);
  });
});
