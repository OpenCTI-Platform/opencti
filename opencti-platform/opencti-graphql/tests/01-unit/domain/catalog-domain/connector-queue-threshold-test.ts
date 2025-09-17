import { describe, expect, it } from 'vitest';
import { computeConnectorTargetContract, validateContractConfigurations } from '../../../../src/modules/catalog/catalog-domain';
import type { CatalogContract } from '../../../../src/modules/catalog/catalog-types';
import type { ConnectorContractConfiguration, ContractConfigInput } from '../../../../src/generated/graphql';

const createMitreContract = (): CatalogContract => ({
  title: 'MITRE ATT&CK',
  slug: 'mitre-attack',
  description: 'MITRE ATT&CK connector',
  short_description: 'Import MITRE ATT&CK data',
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
  container_image: 'mitre-image',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'mitre-schema',
    type: 'object',
    properties: {
      MITRE_URL: {
        type: 'string',
        description: 'MITRE ATT&CK URL',
        default: 'https://attack.mitre.org'
      },
      CONNECTOR_QUEUE_THRESHOLD: {
        default: null,
        description: 'Connector queue max size in Mbytes. Default to 500.',
        exclusiveMinimum: 0,
        type: 'integer'
      } as any, // Use any to bypass TypeScript constraint for testing
      INTERVAL: {
        type: 'integer',
        description: 'Interval in hours',
        default: 24
      }
    },
    required: ['MITRE_URL'], // CONNECTOR_QUEUE_THRESHOLD is NOT required
    additionalProperties: false
  }
});

describe('CONNECTOR_QUEUE_THRESHOLD bug fix', () => {
  // Use a valid 2048-bit RSA public key for testing
  const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
+qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
mwIDAQAB
-----END PUBLIC KEY-----`;

  describe('Password field encryption', () => {
    it('should encrypt password fields in connector configuration', () => {
      const contractWithPassword: CatalogContract = {
        ...createMitreContract(),
        config_schema: {
          ...createMitreContract().config_schema,
          properties: {
            ...createMitreContract().config_schema.properties,
            API_KEY: {
              type: 'string',
              format: 'password',
              description: 'API key for authentication'
            } as any // Use any to bypass TypeScript constraint for testing
          },
          required: ['MITRE_URL', 'API_KEY']
        }
      };

      const configurations: ContractConfigInput[] = [
        { key: 'MITRE_URL', value: 'https://attack.mitre.org' },
        { key: 'API_KEY', value: 'my-secret-api-key' }
      ];

      const result = computeConnectorTargetContract(configurations, contractWithPassword, publicKey);

      // API_KEY should be encrypted
      const apiKeyConfig = result.find((c) => c.key === 'API_KEY');
      expect(apiKeyConfig).toBeDefined();
      expect(apiKeyConfig?.value).not.toBe('my-secret-api-key'); // Should be encrypted
      expect(apiKeyConfig?.encrypted).toBe(true);

      // Other fields should not be encrypted
      const urlConfig = result.find((c) => c.key === 'MITRE_URL');
      expect(urlConfig?.value).toBe('https://attack.mitre.org');
      expect(urlConfig?.encrypted).toBeUndefined();
    });

    it('should handle optional password fields', () => {
      const contractWithOptionalPassword: CatalogContract = {
        ...createMitreContract(),
        config_schema: {
          ...createMitreContract().config_schema,
          properties: {
            ...createMitreContract().config_schema.properties,
            PROXY_PASSWORD: {
              type: 'string',
              format: 'password',
              description: 'Optional proxy password'
            } as any // Use any to bypass TypeScript constraint for testing
          }
          // PROXY_PASSWORD is not in required array
        }
      };

      // Configuration without the optional password
      const configurations: ContractConfigInput[] = [
        { key: 'MITRE_URL', value: 'https://attack.mitre.org' }
        // PROXY_PASSWORD not provided
      ];

      const result = computeConnectorTargetContract(configurations, contractWithOptionalPassword, publicKey);

      // Should not include the optional password field
      expect(result.find((c) => c.key === 'PROXY_PASSWORD')).toBeUndefined();
      expect(result.find((c) => c.key === 'MITRE_URL')).toBeDefined();
    });

    it('should handle multiple password fields', () => {
      const contractWithMultiplePasswords: CatalogContract = {
        ...createMitreContract(),
        config_schema: {
          ...createMitreContract().config_schema,
          properties: {
            USERNAME: {
              type: 'string',
              description: 'Username'
            } as any, // Use any to bypass TypeScript constraint for testing
            PASSWORD: {
              type: 'string',
              format: 'password',
              description: 'User password'
            } as any, // Use any to bypass TypeScript constraint for testing
            API_KEY: {
              type: 'string',
              format: 'password',
              description: 'API key'
            } as any, // Use any to bypass TypeScript constraint for testing
            PROXY_PASSWORD: {
              type: 'string',
              format: 'password',
              description: 'Proxy password'
            } as any // Use any to bypass TypeScript constraint for testing
          },
          required: ['USERNAME', 'PASSWORD', 'API_KEY']
        }
      };

      const configurations: ContractConfigInput[] = [
        { key: 'USERNAME', value: 'admin' },
        { key: 'PASSWORD', value: 'user-password' },
        { key: 'API_KEY', value: 'api-key-value' },
        { key: 'PROXY_PASSWORD', value: 'proxy-pass' }
      ];

      const result = computeConnectorTargetContract(configurations, contractWithMultiplePasswords, publicKey);

      // All password fields should be encrypted
      const passwordConfig = result.find((c) => c.key === 'PASSWORD');
      expect(passwordConfig?.encrypted).toBe(true);
      expect(passwordConfig?.value).not.toBe('user-password');

      const apiKeyConfig = result.find((c) => c.key === 'API_KEY');
      expect(apiKeyConfig?.encrypted).toBe(true);
      expect(apiKeyConfig?.value).not.toBe('api-key-value');

      const proxyPasswordConfig = result.find((c) => c.key === 'PROXY_PASSWORD');
      expect(proxyPasswordConfig?.encrypted).toBe(true);
      expect(proxyPasswordConfig?.value).not.toBe('proxy-pass');

      // Non-password field should not be encrypted
      const usernameConfig = result.find((c) => c.key === 'USERNAME');
      expect(usernameConfig?.encrypted).toBeUndefined();
      expect(usernameConfig?.value).toBe('admin');
    });

    it('should validate configurations with encrypted passwords', () => {
      const contractWithPassword: CatalogContract = {
        ...createMitreContract(),
        config_schema: {
          ...createMitreContract().config_schema,
          properties: {
            ...createMitreContract().config_schema.properties,
            SECRET: {
              type: 'string',
              format: 'password',
              description: 'Secret key'
            } as any // Use any to bypass TypeScript constraint for testing
          },
          required: ['MITRE_URL', 'SECRET']
        }
      };

      // Configuration with encrypted password
      const configurations: ConnectorContractConfiguration[] = [
        { key: 'MITRE_URL', value: 'https://attack.mitre.org' },
        {
          key: 'SECRET',
          value: 'AQEAAf8AAABAwOL5+encrypted_value', // Already encrypted
          encrypted: true
        }
      ];

      // Should validate without throwing
      expect(() => {
        validateContractConfigurations(configurations, contractWithPassword);
      }).not.toThrow();
    });

    it('should handle empty password value', () => {
      const contractWithPassword: CatalogContract = {
        ...createMitreContract(),
        config_schema: {
          ...createMitreContract().config_schema,
          properties: {
            ...createMitreContract().config_schema.properties,
            PASSWORD: {
              type: 'string',
              format: 'password',
              description: 'Optional password'
            } as any // Use any to bypass TypeScript constraint for testing
          }
          // PASSWORD is NOT in required array, making it optional
        }
      };

      const configurations: ContractConfigInput[] = [
        { key: 'MITRE_URL', value: 'https://attack.mitre.org' },
        { key: 'PASSWORD', value: '' } // Empty password
      ];

      // Empty password should be handled (returns null)
      const result = computeConnectorTargetContract(configurations, contractWithPassword, publicKey);

      // Should not include empty password in result
      expect(result.find((c) => c.key === 'PASSWORD')).toBeUndefined();
      expect(result.find((c) => c.key === 'MITRE_URL')).toBeDefined();
    });
  });

  it('should handle optional CONNECTOR_QUEUE_THRESHOLD when not provided', () => {
    const contract = createMitreContract();

    // Only providing required field
    const configurations: ContractConfigInput[] = [
      { key: 'MITRE_URL', value: 'https://attack.mitre.org' }
      // CONNECTOR_QUEUE_THRESHOLD is not provided
    ];

    // Should not throw error for missing optional field
    expect(() => {
      const result = computeConnectorTargetContract(configurations, contract, publicKey);
      // Verify that MITRE_URL and INTERVAL (with default) are in the result
      expect(result).toHaveLength(2);
      expect(result.find((c) => c.key === 'MITRE_URL')).toBeDefined();
      expect(result.find((c) => c.key === 'INTERVAL')).toBeDefined(); // Has default value
      expect(result.find((c) => c.key === 'CONNECTOR_QUEUE_THRESHOLD')).toBeUndefined(); // No default
    }).not.toThrow();
  });

  it('should validate configurations with missing optional integer field', () => {
    const contract = createMitreContract();

    // Configuration without the optional CONNECTOR_QUEUE_THRESHOLD
    const configurations: ConnectorContractConfiguration[] = [
      { key: 'MITRE_URL', value: 'https://attack.mitre.org' }
    ];

    // Should not throw validation error
    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).not.toThrow();
  });

  it('should handle optional field when provided with valid value', () => {
    const contract = createMitreContract();

    const configurations: ContractConfigInput[] = [
      { key: 'MITRE_URL', value: 'https://attack.mitre.org' },
      { key: 'CONNECTOR_QUEUE_THRESHOLD', value: '1000' }
    ];

    const result = computeConnectorTargetContract(configurations, contract, publicKey);

    expect(result).toHaveLength(3); // MITRE_URL, CONNECTOR_QUEUE_THRESHOLD, and INTERVAL (default)
    expect(result.find((c) => c.key === 'CONNECTOR_QUEUE_THRESHOLD')).toEqual({
      key: 'CONNECTOR_QUEUE_THRESHOLD',
      value: '1000'
    });
  });

  it('should throw error when optional integer field has invalid value', () => {
    const contract = createMitreContract();

    const configurations: ContractConfigInput[] = [
      { key: 'MITRE_URL', value: 'https://attack.mitre.org' },
      { key: 'CONNECTOR_QUEUE_THRESHOLD', value: 'not_a_number' }
    ];

    expect(() => {
      computeConnectorTargetContract(configurations, contract, publicKey);
    }).toThrow('Field "CONNECTOR_QUEUE_THRESHOLD" must be a valid integer');
  });

  it('should handle optional field with default value when not provided', () => {
    const contract = createMitreContract();

    // Test with INTERVAL which has a default value of 24
    const configurations: ContractConfigInput[] = [
      { key: 'MITRE_URL', value: 'https://attack.mitre.org' }
      // INTERVAL not provided, should use default
    ];

    const result = computeConnectorTargetContract(configurations, contract, publicKey);

    // Should include INTERVAL with default value
    const intervalConfig = result.find((c) => c.key === 'INTERVAL');
    expect(intervalConfig).toEqual({
      key: 'INTERVAL',
      value: '24' // default value converted to string
    });
  });

  it('should skip optional fields with null default when not provided', () => {
    const contract = createMitreContract();

    const configurations: ContractConfigInput[] = [
      { key: 'MITRE_URL', value: 'https://attack.mitre.org' }
    ];

    const result = computeConnectorTargetContract(configurations, contract, publicKey);

    // Should NOT include CONNECTOR_QUEUE_THRESHOLD since it has no default
    const queueConfig = result.find((c) => c.key === 'CONNECTOR_QUEUE_THRESHOLD');
    expect(queueConfig).toBeUndefined();
  });

  it('should handle multiple optional fields correctly', () => {
    const complexContract: CatalogContract = {
      ...createMitreContract(),
      config_schema: {
        ...createMitreContract().config_schema,
        properties: {
          REQUIRED_FIELD: {
            type: 'string',
            description: 'Required field',
            default: 'default_value'
          },
          OPTIONAL_WITH_DEFAULT: {
            type: 'integer',
            description: 'Optional with default',
            default: 100
          },
          OPTIONAL_NO_DEFAULT: {
            type: 'integer',
            description: 'Optional without default'
            // No default provided intentionally
          } as any // Use any to bypass TypeScript constraint for testing
        },
        required: ['REQUIRED_FIELD']
      }
    };

    const configurations: ContractConfigInput[] = [
      { key: 'REQUIRED_FIELD', value: 'test' }
      // All optional fields omitted
    ];

    const result = computeConnectorTargetContract(configurations, complexContract, publicKey);

    // Should include required field
    expect(result.find((c) => c.key === 'REQUIRED_FIELD')).toBeDefined();

    // Should include optional field with non-null default
    expect(result.find((c) => c.key === 'OPTIONAL_WITH_DEFAULT')).toEqual({
      key: 'OPTIONAL_WITH_DEFAULT',
      value: '100'
    });

    // Should NOT include optional fields without default
    expect(result.find((c) => c.key === 'OPTIONAL_NO_DEFAULT')).toBeUndefined();
  });
});
