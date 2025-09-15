import { describe, expect, it } from 'vitest';
import { processConfigurationValue } from '../../../../src/modules/catalog/catalog-domain';

// Create a valid test RSA public key
const TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`;

describe('processConfigurationValue', () => {
  it('should validate and return boolean as string', () => {
    const propSchema = { type: 'boolean' };

    const resultTrue = processConfigurationValue(
      'true',
      propSchema,
      'bool_field',
      false,
      TEST_PUBLIC_KEY
    );
    expect(resultTrue).toBe('true');

    const resultFalse = processConfigurationValue(
      'false',
      propSchema,
      'bool_field',
      false,
      TEST_PUBLIC_KEY
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
        false,
        TEST_PUBLIC_KEY
      );
    }).toThrow();

    expect(() => {
      processConfigurationValue(
        'yes',
        propSchema,
        'bool_field',
        false,
        TEST_PUBLIC_KEY
      );
    }).toThrow('Field "bool_field" must be a boolean value (true or false). Received: "yes"');
  });

  it('should validate and convert integer values', () => {
    const propSchema = { type: 'integer' };

    const result = processConfigurationValue(
      '42',
      propSchema,
      'int_field',
      false,
      TEST_PUBLIC_KEY
    );
    expect(result).toBe('42');

    const resultNegative = processConfigurationValue(
      '-10',
      propSchema,
      'int_field',
      false,
      TEST_PUBLIC_KEY
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
        false,
        TEST_PUBLIC_KEY
      );
    }).toThrow();

    expect(() => {
      processConfigurationValue(
        'not_a_number',
        propSchema,
        'int_field',
        false,
        TEST_PUBLIC_KEY
      );
    }).toThrow('Field "int_field" must be a valid integer. Received: "not_a_number"');
  });

  it('should handle array values (already comma-separated)', () => {
    const propSchema = { type: 'array' };

    const result = processConfigurationValue(
      'value1,value2,value3',
      propSchema,
      'array_field',
      false,
      TEST_PUBLIC_KEY
    );
    expect(result).toBe('value1,value2,value3');
  });

  it('should handle string values as default', () => {
    const propSchema = { type: 'string' };

    const result = processConfigurationValue(
      'simple string value',
      propSchema,
      'string_field',
      false,
      TEST_PUBLIC_KEY
    );
    expect(result).toBe('simple string value');
  });

  it('should handle unknown types as strings', () => {
    const propSchema = { type: 'unknown' };

    const result = processConfigurationValue(
      'some value',
      propSchema,
      'unknown_field',
      false,
      TEST_PUBLIC_KEY
    );
    expect(result).toBe('some value');
  });
});
