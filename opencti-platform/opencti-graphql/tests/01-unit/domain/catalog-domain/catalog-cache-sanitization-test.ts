import { describe, expect, it } from 'vitest';
import { buildInternalCatalog } from '../../../../src/modules/catalog/catalog-cache';
import type { CatalogContract, CatalogDefinition } from '../../../../src/modules/catalog/catalog-types';

const buildManagerSupportedContract = (): CatalogContract => ({
  title: 'Manager Supported Connector',
  slug: 'manager-supported-connector',
  description: 'Test contract',
  short_description: 'Test',
  logo: 'logo.png',
  use_cases: [],
  verified: true,
  last_verified_date: '2026-01-01',
  playbook_supported: false,
  max_confidence_level: 100,
  support_version: '1.0.0',
  subscription_link: '',
  source_code: '',
  manager_supported: true,
  container_version: '1.0.0',
  container_image: 'ghcr.io/test/connector:1.0.0',
  container_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'http://json-schema.org/draft-07/schema#',
    $id: 'connector-config',
    type: 'object',
    properties: {
      OPENCTI_URL: { type: 'string', description: 'OpenCTI URL', default: '' },
      OPENCTI_TOKEN: { type: 'string', description: 'OpenCTI token', default: '' },
      CONNECTOR_TYPE: { type: 'string', description: 'Connector type', default: '' },
      CONNECTOR_RUN_AND_TERMINATE: { type: 'boolean', description: 'Run and terminate', default: false },
      api_key: { type: 'string', description: 'API key', default: '' },
    },
    required: ['OPENCTI_URL', 'OPENCTI_TOKEN', 'CONNECTOR_TYPE', 'CONNECTOR_RUN_AND_TERMINATE', 'api_key'],
    additionalProperties: false,
  },
});

describe('catalog-cache sanitization for contractsByImage', () => {
  it('removes excluded OpenCTI runtime variables from manager contract validation schema', () => {
    const catalogDefinition: CatalogDefinition = {
      id: 'catalog-test',
      name: 'Catalog test',
      description: 'Catalog description',
      contracts: [buildManagerSupportedContract()],
    };

    const internalCatalog = buildInternalCatalog([catalogDefinition]);
    const contract = internalCatalog.contractsByImage.get('ghcr.io/test/connector:1.0.0');

    expect(contract).toBeDefined();
    expect(contract?.config_schema.properties.OPENCTI_URL).toBeUndefined();
    expect(contract?.config_schema.properties.OPENCTI_TOKEN).toBeUndefined();
    expect(contract?.config_schema.properties.CONNECTOR_TYPE).toBeUndefined();
    expect(contract?.config_schema.properties.CONNECTOR_RUN_AND_TERMINATE).toBeUndefined();

    expect(contract?.config_schema.required).not.toContain('OPENCTI_URL');
    expect(contract?.config_schema.required).not.toContain('OPENCTI_TOKEN');
    expect(contract?.config_schema.required).not.toContain('CONNECTOR_TYPE');
    expect(contract?.config_schema.required).not.toContain('CONNECTOR_RUN_AND_TERMINATE');
    expect(contract?.config_schema.required).toContain('api_key');
  });
});
