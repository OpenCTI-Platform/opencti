import { describe, expect, it } from 'vitest';
import { getDefaultValueAsString } from '../../../../src/modules/catalog/catalog-domain';

describe('getDefaultValueAsString', () => {
  it('should return null when no default value', () => {
    const propSchema = { type: 'string' };
    const result = getDefaultValueAsString(propSchema);
    expect(result).toBeNull();
  });

  it('should convert handle comma-separated string', () => {
    const propSchema = {
      type: 'array',
      default: 'item1,item2,item3'
    };
    const result = getDefaultValueAsString(propSchema);
    expect(result).toBe('item1,item2,item3');
  });

  it('should handle non-array default for array type', () => {
    const propSchema = {
      type: 'array',
      default: 'single_value'
    };
    const result = getDefaultValueAsString(propSchema);
    expect(result).toBe('single_value');
  });

  it('should convert boolean default to string', () => {
    const propSchemaTrue = {
      type: 'boolean',
      default: true
    };
    const resultTrue = getDefaultValueAsString(propSchemaTrue);
    expect(resultTrue).toBe('true');

    const propSchemaFalse = {
      type: 'boolean',
      default: false
    };
    const resultFalse = getDefaultValueAsString(propSchemaFalse);
    expect(resultFalse).toBe('false');
  });

  it('should convert integer default to string', () => {
    const propSchema = {
      type: 'integer',
      default: 42
    };
    const result = getDefaultValueAsString(propSchema);
    expect(result).toBe('42');

    const propSchemaZero = {
      type: 'integer',
      default: 0
    };
    const resultZero = getDefaultValueAsString(propSchemaZero);
    expect(resultZero).toBe('0');
  });

  it('should handle string default value', () => {
    const propSchema = {
      type: 'string',
      default: 'default_value'
    };
    const result = getDefaultValueAsString(propSchema);
    expect(result).toBe('default_value');
  });

  it('should convert non-string default to string for unknown types', () => {
    const propSchema = {
      type: 'object',
      default: { key: 'value' }
    };
    const result = getDefaultValueAsString(propSchema);
    expect(result).toBe('[object Object]');
  });
});
