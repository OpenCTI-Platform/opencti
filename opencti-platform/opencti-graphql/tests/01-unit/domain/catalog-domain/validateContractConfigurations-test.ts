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

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).toThrow('Invalid contract configuration for Test Contract');
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

    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).toThrow();
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

    // Arrays passed as comma-separated strings will fail validation
    // because AJV expects actual arrays, not strings
    expect(() => {
      validateContractConfigurations(configurations, contract);
    }).toThrow('Invalid contract configuration for Test Contract');
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
});
