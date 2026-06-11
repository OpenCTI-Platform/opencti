import { describe, it, expect } from 'vitest';
import type { IngestionTypedProperty } from '@components/data/IngestionCatalog';
import { augmentPasswordDescriptions, buildContractPropertyGroups } from './buildContractPropertyGroups';
import { ManagerContractProperty } from './reconcileManagedConnectorContractDataWithSchema';

type TestStringProperty = IngestionTypedProperty<'string'> & {
  title?: string;
  deprecated?: boolean;
};

// Minimal IngestionTypedProperty factory
const prop = (overrides: Partial<TestStringProperty> = {}): TestStringProperty => ({
  type: 'string',
  default: '',
  title: 'A field',
  description: 'desc',
  ...overrides,
});

const passwordProp = (overrides: Partial<TestStringProperty> = {}) => prop({ format: 'password', ...overrides });
const deprecatedProp = (overrides: Partial<TestStringProperty> = {}) => prop({ deprecated: true, default: 'default_val', ...overrides });

// ---------------------------------------------------------------------------
// augmentPasswordDescriptions
// ---------------------------------------------------------------------------

describe('augmentPasswordDescriptions', () => {
  it('leaves non-password fields unchanged', () => {
    const properties: ManagerContractProperty[] = [['api_key', prop({ description: 'API key' })]];
    const result = augmentPasswordDescriptions(properties);
    expect(result[0][1].description).toBe('API key');
  });

  it('appends hidden-value note to password fields', () => {
    const properties: ManagerContractProperty[] = [['secret', passwordProp({ description: 'My secret' })]];
    const result = augmentPasswordDescriptions(properties);
    expect(result[0][1].description).toBe('My secret Current value is hidden, but can still be replaced.');
  });

  it('does not mutate the original property', () => {
    const original = passwordProp({ description: 'Original' });
    const properties: ManagerContractProperty[] = [['secret', original]];
    augmentPasswordDescriptions(properties);
    expect(original.description).toBe('Original');
  });

  it('handles a mix of password and non-password fields', () => {
    const properties: ManagerContractProperty[] = [
      ['name', prop({ description: 'Name' })],
      ['pass', passwordProp({ description: 'Pass' })],
      ['other', prop({ description: 'Other' })],
    ];
    const result = augmentPasswordDescriptions(properties);
    expect(result[0][1].description).toBe('Name');
    expect(result[1][1].description).toBe('Pass Current value is hidden, but can still be replaced.');
    expect(result[2][1].description).toBe('Other');
  });
});

// ---------------------------------------------------------------------------
// buildContractPropertyGroups
// ---------------------------------------------------------------------------

describe('buildContractPropertyGroups', () => {
  const required = prop();
  const optional = prop();
  const deprecated = deprecatedProp();

  const properties: ManagerContractProperty[] = [
    ['req_field', required],
    ['opt_field', optional],
    ['dep_field', deprecated],
  ];
  const requiredKeys = ['req_field'];

  it('puts required non-deprecated fields into requiredProperties', () => {
    const { requiredProperties } = buildContractPropertyGroups(properties, requiredKeys);
    expect(requiredProperties.properties).toHaveProperty('req_field');
    expect(requiredProperties.properties).not.toHaveProperty('opt_field');
    expect(requiredProperties.properties).not.toHaveProperty('dep_field');
  });

  it('puts optional non-deprecated fields into optionalProperties', () => {
    const { optionalProperties } = buildContractPropertyGroups(properties, requiredKeys);
    expect(optionalProperties.properties).toHaveProperty('opt_field');
    expect(optionalProperties.properties).not.toHaveProperty('req_field');
    expect(optionalProperties.properties).not.toHaveProperty('dep_field');
  });

  it('puts deprecated fields into deprecatedProperties', () => {
    const { deprecatedProperties } = buildContractPropertyGroups(properties, requiredKeys);
    expect(deprecatedProperties).toHaveProperty('dep_field');
    expect(deprecatedProperties).not.toHaveProperty('req_field');
    expect(deprecatedProperties).not.toHaveProperty('opt_field');
  });

  it('includes required keys (minus deprecated) in requiredProperties.required', () => {
    const { requiredProperties } = buildContractPropertyGroups(properties, requiredKeys);
    expect(requiredProperties.required).toEqual(['req_field']);
  });

  it('strips deprecated keys from requiredProperties.required', () => {
    const mixedRequired = ['req_field', 'dep_field'];
    const { requiredProperties } = buildContractPropertyGroups(properties, mixedRequired);
    expect(requiredProperties.required).not.toContain('dep_field');
    expect(requiredProperties.required).toContain('req_field');
  });

  it('preserves manifest order within each group', () => {
    const ordered: ManagerContractProperty[] = [
      ['b_opt', optional],
      ['a_req', required],
      ['c_dep', deprecated],
    ];
    const { requiredProperties, optionalProperties, deprecatedProperties } = buildContractPropertyGroups(ordered, ['a_req']);
    expect(Object.keys(requiredProperties.properties ?? {})).toEqual(['a_req']);
    expect(Object.keys(optionalProperties.properties ?? {})).toEqual(['b_opt']);
    expect(Object.keys(deprecatedProperties)).toEqual(['c_dep']);
  });

  it('handles an empty properties list', () => {
    const { requiredProperties, optionalProperties, deprecatedProperties } = buildContractPropertyGroups([], []);
    expect(requiredProperties.properties).toEqual({});
    expect(optionalProperties.properties).toEqual({});
    expect(deprecatedProperties).toEqual({});
  });
});
