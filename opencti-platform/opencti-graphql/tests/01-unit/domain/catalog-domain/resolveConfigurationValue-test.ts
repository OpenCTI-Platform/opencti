import { describe, expect, it } from 'vitest';
import { resolveConfigurationValue } from '../../../../src/modules/catalog/catalog-domain';
import type { ConnectorContractConfiguration, ContractConfigInput } from '../../../../src/generated/graphql';

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

describe('resolveConfigurationValue', () => {
  it('should return null when no input and no default', () => {
    const propSchema = { type: 'string' };
    const result = resolveConfigurationValue(
      'field_key',
      propSchema,
      undefined,
      undefined,
      TEST_PUBLIC_KEY
    );
    expect(result).toBeNull();
  });

  it('should use default value when no input provided', () => {
    const propSchema = {
      type: 'string',
      default: 'default_value'
    };
    const result = resolveConfigurationValue(
      'field_key',
      propSchema,
      undefined,
      undefined,
      TEST_PUBLIC_KEY
    );
    expect(result).toEqual({
      key: 'field_key',
      value: 'default_value'
    });
  });

  it('should keep existing password when no new value provided', () => {
    const propSchema = {
      type: 'string',
      format: 'password'
    };
    const existingConfig: ConnectorContractConfiguration = {
      key: 'password_field',
      value: 'encrypted_old_password',
      encrypted: true
    };

    const result = resolveConfigurationValue(
      'password_field',
      propSchema,
      undefined,
      existingConfig,
      TEST_PUBLIC_KEY
    );
    expect(result).toEqual(existingConfig);
  });

  it('should handle empty string value', () => {
    const propSchema = { type: 'string' };
    const inputConfig: ContractConfigInput = {
      key: 'field_key',
      value: ''
    };

    const result = resolveConfigurationValue(
      'field_key',
      propSchema,
      inputConfig,
      undefined,
      TEST_PUBLIC_KEY
    );
    expect(result).toBeNull();
  });

  it('should return existing config when value unchanged', () => {
    const propSchema = { type: 'string' };
    const existingConfig: ConnectorContractConfiguration = {
      key: 'field_key',
      value: 'existing_value'
    };
    const inputConfig: ContractConfigInput = {
      key: 'field_key',
      value: 'existing_value'
    };

    const result = resolveConfigurationValue(
      'field_key',
      propSchema,
      inputConfig,
      existingConfig,
      TEST_PUBLIC_KEY
    );
    expect(result).toEqual(existingConfig);
  });

  it('should process new value for string field', () => {
    const propSchema = { type: 'string' };
    const inputConfig: ContractConfigInput = {
      key: 'field_key',
      value: 'new_value'
    };

    const result = resolveConfigurationValue(
      'field_key',
      propSchema,
      inputConfig,
      undefined,
      TEST_PUBLIC_KEY
    );
    expect(result).toEqual({
      key: 'field_key',
      value: 'new_value'
    });
  });

  it('should validate and process boolean value', () => {
    const propSchema = { type: 'boolean' };
    const inputConfig: ContractConfigInput = {
      key: 'bool_field',
      value: 'true'
    };

    const result = resolveConfigurationValue(
      'bool_field',
      propSchema,
      inputConfig,
      undefined,
      TEST_PUBLIC_KEY
    );
    expect(result).toEqual({
      key: 'bool_field',
      value: 'true'
    });
  });

  it('should validate and process integer value', () => {
    const propSchema = { type: 'integer' };
    const inputConfig: ContractConfigInput = {
      key: 'int_field',
      value: '123'
    };

    const result = resolveConfigurationValue(
      'int_field',
      propSchema,
      inputConfig,
      undefined,
      TEST_PUBLIC_KEY
    );
    expect(result).toEqual({
      key: 'int_field',
      value: '123'
    });
  });
});
