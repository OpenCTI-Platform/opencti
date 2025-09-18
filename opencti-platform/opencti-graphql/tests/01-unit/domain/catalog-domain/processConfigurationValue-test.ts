import { describe, expect, it } from 'vitest';
import { processConfigurationValue } from '../../../../src/modules/catalog/catalog-domain';

describe('processConfigurationValue', () => {
  it('should not process password fields (passwords use separate encryption)', () => {
    // Password fields should be handled by processPasswordConfigurationValue, not processConfigurationValue
    const propSchema = { type: 'string', format: 'password' };

    // processConfigurationValue should just return the raw value for passwords
    // The actual encryption happens in resolveConfigurationValue
    const result = processConfigurationValue(
      'myPassword123',
      propSchema,
      'password_field',
    );

    // Should return the raw value unchanged (encryption happens elsewhere)
    expect(result).toBe('myPassword123');
  });

  it('should validate and return boolean as string', () => {
    const propSchema = { type: 'boolean' };

    const resultTrue = processConfigurationValue(
      'true',
      propSchema,
      'bool_field',
    );
    expect(resultTrue).toBe('true');

    const resultFalse = processConfigurationValue(
      'false',
      propSchema,
      'bool_field',
    );
    expect(resultFalse).toBe('false');
  });

  it('should throw error for invalid boolean value', () => {
    const propSchema = { type: 'boolean' };

    expect(() => {
      processConfigurationValue(
        'yes',
        propSchema,
        'bool_field',
      );
    }).toThrow();

    expect(() => {
      processConfigurationValue(
        'yes',
        propSchema,
        'bool_field',
      );
    }).toThrow('Field "bool_field" must be a boolean value (true or false). Received: "yes"');
  });

  it('should validate and convert integer values', () => {
    const propSchema = { type: 'integer' };

    const result = processConfigurationValue(
      '42',
      propSchema,
      'int_field',
    );
    expect(result).toBe('42');

    const resultNegative = processConfigurationValue(
      '-10',
      propSchema,
      'int_field',
    );
    expect(resultNegative).toBe('-10');
  });

  it('should throw error for invalid integer value', () => {
    const propSchema = { type: 'integer' };

    expect(() => {
      processConfigurationValue(
        'not_a_number',
        propSchema,
        'int_field',
      );
    }).toThrow();

    expect(() => {
      processConfigurationValue(
        'not_a_number',
        propSchema,
        'int_field',
      );
    }).toThrow('Field "int_field" must be a valid integer. Received: "not_a_number"');
  });

  it('should handle array values (already comma-separated)', () => {
    const propSchema = { type: 'array' };

    const result = processConfigurationValue(
      'value1,value2,value3',
      propSchema,
      'array_field',
    );
    expect(result).toBe('value1,value2,value3');
  });

  it('should handle string values as default', () => {
    const propSchema = { type: 'string' };

    const result = processConfigurationValue(
      'simple string value',
      propSchema,
      'string_field',
    );
    expect(result).toBe('simple string value');
  });

  it('should handle unknown types as strings', () => {
    const propSchema = { type: 'unknown' };

    const result = processConfigurationValue(
      'some value',
      propSchema,
      'unknown_field',
    );
    expect(result).toBe('some value');
  });
});
