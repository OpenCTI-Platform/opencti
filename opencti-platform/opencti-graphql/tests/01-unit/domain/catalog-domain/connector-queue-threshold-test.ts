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
  const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC8zJkDUlRZBBrRsFlHF3pow0BH
-----END PUBLIC KEY-----`;

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
