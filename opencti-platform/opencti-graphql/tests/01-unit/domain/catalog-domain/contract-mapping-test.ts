import { describe, expect, it } from 'vitest';
import type { CatalogContract, CatalogContractEntityFields } from '../../../../src/modules/catalog/catalog-types';
import {
  mapContractDtoV0ToContractEntityFields,
  mapContractEntityFieldsToEmbeddedConnectorManagerContract,
  mapContractEntityFieldsToGraphqlCatalogContract,
} from '../../../../src/modules/catalog/catalog-domain';

const buildContractEntityFields = (): CatalogContractEntityFields => ({
  catalog_id: 'catalog-1',
  contract_id: 'ipinfo-1.2.3',
  content_hash: 'hash-1',
  title: 'IPinfo',
  slug: 'ipinfo',
  description: 'desc',
  short_description: 'short',
  logo_uri: '/storage/view/catalog-logos/logo.png',
  use_cases: ['a'],
  verified: true,
  last_verified_date: '2024-01-01',
  playbook_supported: false,
  max_confidence_level: 50,
  support_version: '6.7.0',
  subscription_link: null as unknown as string,
  source_code: '',
  manager_supported: true,
  contract_version: '1.2.3',
  image: 'opencti/connector-ipinfo',
  connector_type: 'EXTERNAL_IMPORT',
  config_schema: {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'schema-id',
    type: 'object',
    properties: {
      OPENCTI_URL: { type: 'string' },
      OPENCTI_TOKEN: { type: 'string', format: 'password' },
      USERNAME: { type: 'string' },
    },
    required: ['OPENCTI_URL', 'OPENCTI_TOKEN', 'USERNAME'],
    additionalProperties: false,
  },
  license_type: 'Free',
  solution_categories: [],
  contact: null as unknown as string,
});

describe('catalog contract mappings', () => {
  it('should normalize V0 support_version when mapping to entity fields', () => {
    const dto: CatalogContract = {
      title: 'IPinfo',
      slug: 'ipinfo',
      description: 'desc',
      short_description: 'short',
      logo: null,
      use_cases: [],
      verified: true,
      last_verified_date: '2024-01-01',
      playbook_supported: false,
      max_confidence_level: 50,
      support_version: '>= 6.7.0',
      subscription_link: null,
      source_code: '',
      manager_supported: true,
      container_version: '1.2.3',
      container_image: 'opencti/connector-ipinfo',
      container_type: 'EXTERNAL_IMPORT',
      config_schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        $id: 'schema-id',
        type: 'object',
        properties: {},
        required: [],
        additionalProperties: true,
      },
      license_type: null,
      solution_categories: [],
      contact: null,
    };
    const mapped = mapContractDtoV0ToContractEntityFields({
      catalogId: 'catalog-1',
      contractDto: dto,
      contractContentHash: 'hash-1',
      logoUri: null,
    });
    expect(mapped.contract_id).toBe('ipinfo-1.2.3');
    expect(mapped.support_version).toBe('6.7.0');
    expect(mapped.contract_version).toBe('1.2.3');
  });

  it('should strip runtime config vars from GraphQL contract mapping when requested', () => {
    const mapped = mapContractEntityFieldsToGraphqlCatalogContract(buildContractEntityFields(), { excludeRuntimeConfigVars: true });
    expect(mapped.config_schema.properties).toEqual({
      USERNAME: { type: 'string' },
    });
    expect(mapped.config_schema.required).toEqual(['USERNAME']);
  });

  it('should keep runtime config vars when GraphQL contract mapping does not request stripping', () => {
    const mapped = mapContractEntityFieldsToGraphqlCatalogContract(buildContractEntityFields());
    expect(Object.keys(mapped.config_schema.properties)).toContain('OPENCTI_URL');
    expect(Object.keys(mapped.config_schema.properties)).toContain('OPENCTI_TOKEN');
  });

  it('should normalize malformed config schema when mapping GraphQL contracts', () => {
    const contract = {
      ...buildContractEntityFields(),
      config_schema: {
        type: 'object',
      },
    } as unknown as CatalogContractEntityFields;
    const mapped = mapContractEntityFieldsToGraphqlCatalogContract(contract, { excludeRuntimeConfigVars: true });
    expect(mapped.config_schema).toMatchObject({
      type: 'object',
      properties: {},
      required: [],
      additionalProperties: true,
    });
  });

  it('should sanitize embedded manager contract snapshot to known fields only', () => {
    const raw = {
      ...buildContractEntityFields(),
      _index: 'internal-objects',
      _score: 1,
      entity_type: 'CatalogContract',
    } as unknown as CatalogContractEntityFields;
    const embedded = mapContractEntityFieldsToEmbeddedConnectorManagerContract(raw);
    expect(embedded).toMatchObject({
      catalog_id: 'catalog-1',
      contract_id: 'ipinfo-1.2.3',
      contract_version: '1.2.3',
      image: 'opencti/connector-ipinfo',
    });
    expect((embedded as any)._index).toBeUndefined();
    expect((embedded as any)._score).toBeUndefined();
    expect((embedded as any).entity_type).toBeUndefined();
  });
});
