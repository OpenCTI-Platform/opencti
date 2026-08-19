import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockFullEntitiesList,
  mockPatchAttribute,
  mockListCatalogContractLogos,
  mockStoreCatalogContractLogo,
  mockComputeContractContentHash,
  mockMapCatalogContractDtoToCatalogContractSyncSource,
  mockMapContractDtoV0ToContractEntityFields,
} = vi.hoisted(() => ({
  mockFullEntitiesList: vi.fn(),
  mockPatchAttribute: vi.fn(),
  mockListCatalogContractLogos: vi.fn(),
  mockStoreCatalogContractLogo: vi.fn(),
  mockComputeContractContentHash: vi.fn(),
  mockMapCatalogContractDtoToCatalogContractSyncSource: vi.fn(),
  mockMapContractDtoV0ToContractEntityFields: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: vi.fn((key: string) => {
        if (key === 'redis:ca') return [];
        if (key === 'redis:use_ssl') return false;
        return undefined;
      }),
    },
    logMigration: {
      info: vi.fn(),
      error: vi.fn(),
      warn: vi.fn(),
      debug: vi.fn(),
    },
  };
});

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: mockFullEntitiesList,
}));

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: mockPatchAttribute,
}));

vi.mock('../../../src/utils/access', () => ({
  executionContext: vi.fn(() => ({ source: 'migration' })),
  SYSTEM_USER: { id: 'system-user' },
}));

vi.mock('../../../src/modules/catalog/catalog-logo-storage', () => ({
  listCatalogContractLogos: mockListCatalogContractLogos,
  storeCatalogContractLogo: mockStoreCatalogContractLogo,
}));

vi.mock('../../../src/modules/catalog/sync/catalog-sync-domain', () => ({
  computeContractContentHash: mockComputeContractContentHash,
}));

vi.mock('../../../src/modules/catalog/sync/catalog-sync-source-gateway', () => ({
  mapCatalogContractDtoToCatalogContractSyncSource: mockMapCatalogContractDtoToCatalogContractSyncSource,
}));

vi.mock('../../../src/modules/catalog/catalog-domain', () => ({
  mapContractDtoV0ToContractEntityFields: mockMapContractDtoV0ToContractEntityFields,
}));

vi.mock('../../../src/__generated__/opencti-manifest.json', () => ({
  default: {
    id: 'filigran-catalog',
    contracts: [
      {
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
        support_version: '6.7.0',
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
      },
    ],
  },
}));

import { up } from '../../../src/migrations/1786264797376-embed-catalog-contract-in-connector-entity';

const runUp = async () => {
  await new Promise<void>((resolve, reject) => {
    up((error?: Error) => {
      if (error) reject(error);
      else resolve();
    });
  });
};

describe('migration 1786264797376 embed catalog contract', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockListCatalogContractLogos.mockResolvedValue(new Set<string>());
    mockStoreCatalogContractLogo.mockResolvedValue({ result: 'success', existed: false, logoUri: '/storage/view/catalog-logos/logo.png', filename: 'logo.png' });
    mockMapCatalogContractDtoToCatalogContractSyncSource.mockReturnValue({ id: 'ipinfo-1.2.3' });
    mockComputeContractContentHash.mockReturnValue('hash-1');
    mockMapContractDtoV0ToContractEntityFields.mockReturnValue({ contract_id: 'ipinfo-1.2.3', image: 'opencti/connector-ipinfo' });
    mockPatchAttribute.mockResolvedValue(undefined);
  });

  it('should patch missing manager_contract and missing manager_upgrade_strategy', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-1',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: undefined,
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-1',
      'Connector',
      expect.objectContaining({
        manager_upgrade_strategy: 'latest',
      }),
    );
    const patch = mockPatchAttribute.mock.calls[0][4];
    expect(patch.manager_contract).toBeDefined();
  });

  it('should only patch upgrade strategy when manager contract snapshot already exists', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-2',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: { contract_id: 'ipinfo-1.2.3' },
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    const patch = mockPatchAttribute.mock.calls[0][4];
    expect(patch.manager_upgrade_strategy).toBe('latest');
    expect(patch.manager_contract).toBeUndefined();
  });

  it('should not patch connectors that already have manager contract and strategy', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-3',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: { contract_id: 'ipinfo-1.2.3' },
      manager_upgrade_strategy: 'latest',
    }]);
    await runUp();
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('should still patch upgrade strategy when contract is missing from manifest', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-4',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-unknown',
      manager_contract: undefined,
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-4',
      'Connector',
      { manager_upgrade_strategy: 'latest' },
    );
  });

  it('should patch manager_contract even when logo storage fails', async () => {
    mockStoreCatalogContractLogo.mockResolvedValue({
      result: 'failed',
      logoUri: null,
      error: new Error('logo upload failed'),
    });
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-5',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: undefined,
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    const patch = mockPatchAttribute.mock.calls[0][4];
    expect(patch.manager_contract).toBeDefined();
    expect(patch.manager_upgrade_strategy).toBe('latest');
  });
});
