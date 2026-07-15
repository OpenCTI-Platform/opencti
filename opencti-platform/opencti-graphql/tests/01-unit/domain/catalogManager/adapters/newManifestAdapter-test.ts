import { describe, expect, it } from 'vitest';

import { NewManifestAdapter } from '../../../../../src/modules/catalog/catalog-adapters';

const fixtureManifest = {
  id: 'catalog-v2',
  name: 'Catalog v2',
  description: 'Fixture for adapter tests',
  manifest_schema_version: '16.0.0',
  manifest_version: '7.260701.0',
  product_version: '7.260701.0',
  contracts: [
    {
      id: null,
      title: 'Ipinfo',
      slug: 'ipinfo',
      description: 'ipinfo contract',
      short_description: 'ipinfo short',
      logo: 'logo.png',
      use_cases: ['Commercial Threat Intel'],
      verified: true,
      last_verified_date: null,
      subscription_link: 'https://example.test/ipinfo',
      source_code: 'https://example.test/source',
      manager_supported: true,
      support_version: '>=7.0.0',
      version: 'rolling',
      image_name: 'opencti/connector-ipinfo',
      image_type: 'EXTERNAL_IMPORT',
      additional_properties: {
        max_confidence_level: 75,
        playbook_supported: false,
      },
      config_schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        $id: 'https://example.test/ipinfo.schema.json',
        type: 'object',
        properties: {
          CONNECTOR_NAME: { type: 'string', default: 'Ipinfo', description: 'name' },
        },
        required: [],
        additionalProperties: true,
      },
    },
    {
      id: 'contract-2',
      title: 'Threatmatch',
      slug: 'threatmatch',
      description: 'threatmatch contract',
      short_description: 'threatmatch short',
      logo: 'logo.png',
      use_cases: ['Open Source Threat Intel'],
      verified: false,
      last_verified_date: null,
      subscription_link: '',
      source_code: 'https://example.test/source',
      manager_supported: false,
      support_version: '>=7.0.0',
      version: '1.0.0',
      image_name: 'opencti/connector-threatmatch',
      image_type: 'EXTERNAL_IMPORT',
      additional_properties: {},
      config_schema: {
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        $id: 'https://example.test/threatmatch.schema.json',
        type: 'object',
        properties: {},
        required: [],
        additionalProperties: true,
      },
    },
  ],
};

describe('NewManifestAdapter', () => {
  it('maps TDR-16 manifest contract fields into internal catalog shape keyed by image_name', () => {
    const adapter = new NewManifestAdapter();

    const internal = adapter.toInternalCatalog(fixtureManifest);

    expect(Object.keys(internal.catalogMap)).toEqual(['catalog-v2']);
    expect(internal.contractsByImage.has('opencti/connector-ipinfo')).toBeTruthy();
    expect(internal.contractsByImage.has('opencti/connector-threatmatch')).toBeTruthy();

    const contract = internal.contractsByImage.get('opencti/connector-ipinfo');
    expect(contract?.container_image).toBe('opencti/connector-ipinfo');
    expect(contract?.container_type).toBe('EXTERNAL_IMPORT');
    expect(contract?.max_confidence_level).toBe(75);
    expect(contract?.manager_supported).toBeTruthy();
  });

  it('rejects unsupported manifest schema versions', () => {
    const adapter = new NewManifestAdapter();

    expect(() => adapter.toInternalCatalog({
      ...fixtureManifest,
      manifest_schema_version: '2.0.0',
    })).toThrow();
  });
});
