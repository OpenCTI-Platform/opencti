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

  it('rejects a manifest missing required top-level fields (id, contracts)', () => {
    const adapter = new NewManifestAdapter();

    expect(() => adapter.toInternalCatalog({ manifest_schema_version: '1' })).toThrow();
    expect(() => adapter.toInternalCatalog({ id: 'catalog-v2' })).toThrow();
  });

  it('accepts any manifest_schema_version value as long as id and contracts are present', () => {
    const adapter = new NewManifestAdapter();

    for (const version of ['1', '16.0.0', '99.0', 'future']) {
      const internal = adapter.toInternalCatalog({ ...fixtureManifest, manifest_schema_version: version });
      expect(Object.keys(internal.catalogMap)).toEqual(['catalog-v2']);
    }
  });

  it('keeps all contracts but exposes latest contract per slug for catalog queries', () => {
    const adapter = new NewManifestAdapter();

    const manifestWithTwoVersions = {
      ...fixtureManifest,
      contracts: [
        {
          ...fixtureManifest.contracts[0],
          id: 'ipinfo-1.4.0',
          integration_name: 'ipinfo-1.4.0',
          version: '1.4.0',
        },
        {
          ...fixtureManifest.contracts[0],
          id: 'ipinfo-1.5.2',
          integration_name: 'ipinfo-1.5.2',
          version: '1.5.2',
          support_version: '>=7.3.0',
        },
      ],
    };

    const internal = adapter.toInternalCatalog(manifestWithTwoVersions);
    const catalog = internal.catalogMap['catalog-v2'];

    // Latest by slug (last manifest occurrence) is exposed in catalog query view.
    expect(catalog.definition.contracts).toHaveLength(1);
    expect(catalog.definition.contracts[0].slug).toBe('ipinfo');
    expect(catalog.definition.contracts[0].container_version).toBe('1.5.2');

    // All contracts are retained for next workflows.
    expect(internal.allContracts).toBeDefined();
    expect(internal.allContracts).toHaveLength(2);
    expect(internal.latestContractsBySlug?.get('ipinfo')?.container_version).toBe('1.5.2');

    // Metadata from new manifest is preserved.
    expect(internal.allContracts?.[0].id).toBe('ipinfo-1.4.0');
    expect(internal.allContracts?.[1].integration_name).toBe('ipinfo-1.5.2');
  });
});
