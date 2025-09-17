import { describe, expect, it } from 'vitest';
import { validateContractConfigurations } from '../../../../src/modules/catalog/catalog-domain';
import type { CatalogContract } from '../../../../src/modules/catalog/catalog-types';
import type { ConnectorContractConfiguration } from '../../../../src/generated/graphql';

const createTestContract = (properties: any, required: string[] = []): CatalogContract => ({
  title: 'Test Contract',
  slug: 'test-contract',
  description: 'Test description',
  short_description: 'Short desc',
  logo: 'logo.png',
  use_cases: [],
  verified: true,
  last_verified_date: '2024-01-01',
  playbook_supported: false,
  max_confidence_level: 100,
  support_version: '1.0.0',
  subscription_link: '',
  source_code: '',
  manager_supported: true,
  container_version: '1.0.0',
  container_image: 'test-image',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'test-schema',
    type: 'object',
    properties,
    required,
    additionalProperties: false
  }
});

describe('validateContractConfigurations', () => {
  it('should validate configuration with all required fields', () => {
    const contract = createTestContract(
      {
        name: { type: 'string' },
        port: { type: 'integer' },
        enabled: { type: 'boolean' }
      },
      ['name', 'port', 'enabled']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'name', value: 'test-service' },
      { key: 'port', value: '8080' },
      { key: 'enabled', value: 'true' }
    ];

    // Should not throw
    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should throw error when required field is missing', () => {
    const contract = createTestContract(
      {
        name: { type: 'string' },
        port: { type: 'integer' }
      },
      ['name', 'port']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'name', value: 'test-service' }
      // port is missing
    ];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).toThrow();

    try {
      validateContractConfigurations(configurations, contract);
    } catch (error: any) {
      expect(error.message).toContain('Invalid contract configuration for Test Contract');
      expect(error.message).toContain('Missing required field: "port"');
    }
  });

  it('should handle optional fields correctly', () => {
    const contract = createTestContract(
      {
        name: { type: 'string' },
        description: { type: 'string' }
      },
      ['name'] // only name is required
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'name', value: 'test-service' }
      // description is optional and not provided
    ];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should handle type coercion with AJV', () => {
    const contract = createTestContract(
      {
        port: { type: 'integer' },
        enabled: { type: 'boolean' }
      },
      ['port', 'enabled']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'port', value: '8080' }, // string that can be coerced to integer
      { key: 'enabled', value: 'true' } // string that can be coerced to boolean
    ];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should throw error for invalid type that cannot be coerced', () => {
    const contract = createTestContract(
      {
        port: { type: 'integer' }
      },
      ['port']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'port', value: 'not_a_number' }
    ];

    try {
      validateContractConfigurations(configurations, contract);
      // Should not reach here
      expect(true).toBe(false);
    } catch (error: any) {
      expect(error.message).toContain('Invalid contract configuration for Test Contract');
      // AJV will report type error since string cannot be coerced to integer
      expect(error.message).toMatch(/Field "port" must be of type (integer|number)/);
    }
  });

  it('should handle array type in configuration', () => {
    const contract = createTestContract(
      {
        tags: { type: 'array', items: { type: 'string' } }
      },
      ['tags']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'tags', value: 'tag1,tag2,tag3' }
    ];

    // Arrays passed as comma-separated strings should now work
    // The validation function converts them to arrays for AJV
    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should handle empty array from comma-separated string', () => {
    const contract = createTestContract(
      {
        tags: { type: 'array', items: { type: 'string' } }
      },
      [] // tags is optional
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'tags', value: '' } // empty string should become empty array
    ];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should handle array with spaces in comma-separated values', () => {
    const contract = createTestContract(
      {
        scopes: { type: 'array', items: { type: 'string' } }
      },
      ['scopes']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'scopes', value: 'greynoisefeed, toto ,  test  ' } // with spaces
    ];

    // Should trim spaces and validate correctly
    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should ignore null or undefined values in configuration', () => {
    const contract = createTestContract(
      {
        name: { type: 'string' },
        optional1: { type: 'string' },
        optional2: { type: 'string' }
      },
      ['name']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'name', value: 'test' },
      { key: 'optional1', value: undefined as any },
      { key: 'optional2', value: null as any }
    ];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should validate complex schema with multiple types', () => {
    const contract = createTestContract(
      {
        name: { type: 'string' },
        port: { type: 'integer' },
        enabled: { type: 'boolean' },
        timeout: { type: 'integer' }
      },
      ['name', 'port', 'enabled']
    );

    const configurations: ConnectorContractConfiguration[] = [
      { key: 'name', value: 'complex-service' },
      { key: 'port', value: '3000' },
      { key: 'enabled', value: 'false' },
      { key: 'timeout', value: '30' }
    ];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should handle empty configuration array for schema with no required fields', () => {
    const contract = createTestContract(
      {
        optional: { type: 'string' }
      },
      [] // no required fields
    );

    const configurations: ConnectorContractConfiguration[] = [];

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  describe('Encrypted field validation', () => {
    it('should validate encrypted password fields', () => {
      const contract = createTestContract(
        {
          username: { type: 'string' },
          password: { type: 'string', format: 'password' }
        },
        ['username', 'password']
      );

      const configurations: ConnectorContractConfiguration[] = [
        { key: 'username', value: 'admin' },
        {
          key: 'password',
          value: 'AQEAAf8AAABAwOL5+encrypted_base64_value', // Encrypted value
          encrypted: true
        }
      ];

      // Should validate encrypted passwords successfully
      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).not.toThrow();
    });

    it('should validate unencrypted password fields', () => {
      const contract = createTestContract(
        {
          api_key: { type: 'string', format: 'password' }
        },
        ['api_key']
      );

      const configurations: ConnectorContractConfiguration[] = [
        {
          key: 'api_key',
          value: 'plain_text_api_key' // Unencrypted password (not tagged as encrypted)
        }
      ];

      // Should still validate unencrypted passwords
      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).not.toThrow();
    });

    it('should handle multiple password fields', () => {
      const contract = createTestContract(
        {
          primary_password: { type: 'string', format: 'password' },
          secondary_password: { type: 'string', format: 'password' },
          api_token: { type: 'string', format: 'password' }
        },
        ['primary_password', 'secondary_password']
      );

      const configurations: ConnectorContractConfiguration[] = [
        {
          key: 'primary_password',
          value: 'encrypted_primary',
          encrypted: true
        },
        {
          key: 'secondary_password',
          value: 'encrypted_secondary',
          encrypted: true
        },
        {
          key: 'api_token',
          value: 'optional_encrypted_token',
          encrypted: true
        }
      ];

      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).not.toThrow();
    });

    it('should validate mixed encrypted and non-encrypted fields', () => {
      const contract = createTestContract(
        {
          host: { type: 'string' },
          port: { type: 'integer' },
          password: { type: 'string', format: 'password' },
          ssl_enabled: { type: 'boolean' }
        },
        ['host', 'port', 'password']
      );

      const configurations: ConnectorContractConfiguration[] = [
        { key: 'host', value: 'example.com' },
        { key: 'port', value: '443' },
        {
          key: 'password',
          value: 'encrypted_password_value',
          encrypted: true
        },
        { key: 'ssl_enabled', value: 'true' }
      ];

      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).not.toThrow();
    });

    it('should ignore encrypted flag on non-password fields', () => {
      const contract = createTestContract(
        {
          username: { type: 'string' },
          count: { type: 'integer' }
        },
        ['username', 'count']
      );

      const configurations: ConnectorContractConfiguration[] = [
        {
          key: 'username',
          value: 'john_doe',
          encrypted: true // Incorrectly marked as encrypted
        },
        { key: 'count', value: '42' }
      ];

      // Should validate even with incorrect encrypted flag
      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).not.toThrow();
    });

    it('should validate empty password field', () => {
      const contract = createTestContract(
        {
          optional_password: { type: 'string', format: 'password' }
        },
        [] // Password is optional
      );

      const configurations: ConnectorContractConfiguration[] = [
        // No password provided
      ];

      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).not.toThrow();
    });

    it('should fail validation for missing required password', () => {
      const contract = createTestContract(
        {
          auth_token: { type: 'string', format: 'password' }
        },
        ['auth_token'] // Password is required
      );

      const configurations: ConnectorContractConfiguration[] = [
        // Password not provided
      ];

      expect(() => {
        validateContractConfigurations(configurations, contract);
      }).toThrow('Missing required field: "auth_token"');
    });
  });
});
