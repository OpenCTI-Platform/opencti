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

  describe('Password encryption', () => {
    it('should encrypt new password value', () => {
      const propSchema = {
        type: 'string',
        format: 'password'
      };
      const inputConfig: ContractConfigInput = {
        key: 'password_field',
        value: 'newPassword123'
      };

      const result = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        undefined,
        TEST_PUBLIC_KEY
      );

      expect(result).toBeDefined();
      expect(result?.key).toBe('password_field');
      expect(result?.value).not.toBe('newPassword123'); // Should be encrypted
      expect(result?.encrypted).toBe(true); // Should have encrypted flag

      // Verify it's base64 encoded
      if (result && result.value) {
        const encryptedValue = result.value;
        expect(() => Buffer.from(encryptedValue, 'base64')).not.toThrow();
      }
    });

    it('should replace existing password with new encrypted value', () => {
      const propSchema = {
        type: 'string',
        format: 'password'
      };
      const existingConfig: ConnectorContractConfiguration = {
        key: 'password_field',
        value: 'old_encrypted_value',
        encrypted: true
      };
      const inputConfig: ContractConfigInput = {
        key: 'password_field',
        value: 'brandNewPassword456'
      };

      const result = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        existingConfig,
        TEST_PUBLIC_KEY
      );

      expect(result).toBeDefined();
      expect(result?.key).toBe('password_field');
      expect(result?.value).not.toBe('brandNewPassword456'); // Should be encrypted
      expect(result?.value).not.toBe('old_encrypted_value'); // Should be different from old
      expect(result?.encrypted).toBe(true);
    });

    it('should handle empty password encryption', () => {
      const propSchema = {
        type: 'string',
        format: 'password'
      };
      const inputConfig: ContractConfigInput = {
        key: 'password_field',
        value: '' // Empty password
      };

      const result = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        undefined,
        TEST_PUBLIC_KEY
      );

      // Empty string should return null (no value)
      expect(result).toBeNull();
    });

    it('should not re-encrypt when password value unchanged', () => {
      const propSchema = {
        type: 'string',
        format: 'password'
      };
      const existingConfig: ConnectorContractConfiguration = {
        key: 'password_field',
        value: 'existing_encrypted_value',
        encrypted: true
      };
      const inputConfig: ContractConfigInput = {
        key: 'password_field',
        value: 'existing_encrypted_value' // Same value
      };

      const result = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        existingConfig,
        TEST_PUBLIC_KEY
      );

      // Should return the existing config unchanged
      expect(result).toEqual(existingConfig);
    });

    it('should encrypt password with special characters', () => {
      const propSchema = {
        type: 'string',
        format: 'password'
      };
      const inputConfig: ContractConfigInput = {
        key: 'password_field',
        value: '!@#$%^&*()_+-=[]{}|;\':",./<>?'
      };

      const result = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        undefined,
        TEST_PUBLIC_KEY
      );

      expect(result).toBeDefined();
      expect(result?.encrypted).toBe(true);
      expect(result?.value).not.toContain('!@#$%'); // Should be encrypted
    });

    it('should use default password value when not provided', () => {
      const propSchema = {
        type: 'string',
        format: 'password',
        default: 'defaultPassword'
      };

      const result = resolveConfigurationValue(
        'password_field',
        propSchema,
        undefined,
        undefined,
        TEST_PUBLIC_KEY
      );

      // Default passwords should not be encrypted automatically
      // They should be treated as regular defaults
      expect(result).toEqual({
        key: 'password_field',
        value: 'defaultPassword'
      });
    });

    it('should validate password encryption produces different values each time', () => {
      const propSchema = {
        type: 'string',
        format: 'password'
      };
      const inputConfig: ContractConfigInput = {
        key: 'password_field',
        value: 'samePassword'
      };

      const result1 = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        undefined,
        TEST_PUBLIC_KEY
      );

      const result2 = resolveConfigurationValue(
        'password_field',
        propSchema,
        inputConfig,
        undefined,
        TEST_PUBLIC_KEY
      );

      // Same password should produce different encrypted values (due to random AES key)
      expect(result1?.value).not.toBe(result2?.value);
      expect(result1?.encrypted).toBe(true);
      expect(result2?.encrypted).toBe(true);
    });
  });
});
