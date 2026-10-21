import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockFullEntitiesList,
  mockPatchAttribute,
  mockListCatalogContractLogos,
  mockStoreCatalogContractLogo,
  mockComputeContractContentHash,
  mockMapCatalogContractDtoToCatalogContractSyncSource,
  mockMapContractDtoV0ToContractEntityFields,
  mockMapContractEntityFieldsToEmbeddedConnectorManagerContract,
  mockFindCatalogByCatalogId,
  mockFindLatestCompatibleCatalogContractByImageName,
} = vi.hoisted(() => ({
  mockFullEntitiesList: vi.fn(),
  mockPatchAttribute: vi.fn(),
  mockListCatalogContractLogos: vi.fn(),
  mockStoreCatalogContractLogo: vi.fn(),
  mockComputeContractContentHash: vi.fn(),
  mockMapCatalogContractDtoToCatalogContractSyncSource: vi.fn(),
  mockMapContractDtoV0ToContractEntityFields: vi.fn(),
  mockMapContractEntityFieldsToEmbeddedConnectorManagerContract: vi.fn(),
  mockFindCatalogByCatalogId: vi.fn(),
  mockFindLatestCompatibleCatalogContractByImageName: vi.fn(),
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

vi.mock('../../../src/modules/catalog/catalog-repository', () => ({
  findCatalogByCatalogId: mockFindCatalogByCatalogId,
  findLatestCompatibleCatalogContractByImageName: mockFindLatestCompatibleCatalogContractByImageName,
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
  mapContractEntityFieldsToEmbeddedConnectorManagerContract: mockMapContractEntityFieldsToEmbeddedConnectorManagerContract,
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

import { logMigration } from '../../../src/config/conf';
import { up } from '../../../src/migrations/1792531384498-fix-managed-connectors-wrong-catalog-id';

const runUp = async () => {
  await new Promise<void>((resolve, reject) => {
    void up((error?: Error) => {
      if (error) reject(error);
      else resolve();
    });
  });
};

describe('migration 1792531384498 leftover managed connectors contract snapshot', () => {
  const customCatalogContract = { catalog_id: 'custom-catalog', contract_id: 'custom-1.0.0', image: 'acme/connector-custom' };

  beforeEach(() => {
    vi.clearAllMocks();
    mockFindCatalogByCatalogId.mockImplementation(async (_context, _user, catalogId: string) => {
      return catalogId === 'custom-catalog' ? { catalog_id: 'custom-catalog' } : undefined;
    });
    mockFindLatestCompatibleCatalogContractByImageName.mockResolvedValue(customCatalogContract);
    mockMapContractEntityFieldsToEmbeddedConnectorManagerContract.mockImplementation((contract) => ({ ...contract, embedded: true }));
    mockListCatalogContractLogos.mockResolvedValue(new Set<string>());
    mockStoreCatalogContractLogo.mockResolvedValue({ result: 'success', existed: false, logoUri: '/storage/view/catalog-logos/logo.png', filename: 'logo.png' });
    mockMapCatalogContractDtoToCatalogContractSyncSource.mockReturnValue({ id: 'ipinfo-1.2.3' });
    mockComputeContractContentHash.mockReturnValue('hash-1');
    mockMapContractDtoV0ToContractEntityFields.mockReturnValue({ catalog_id: 'filigran-catalog', contract_id: 'ipinfo-1.2.3', image: 'opencti/connector-ipinfo' });
    mockPatchAttribute.mockResolvedValue(undefined);
  });

  it('should embed the contract of the catalog found in ES', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-1',
      catalog_id: 'custom-catalog',
      manager_contract_image: 'acme/connector-custom',
      manager_contract: undefined,
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    expect(mockFindLatestCompatibleCatalogContractByImageName).toHaveBeenCalledWith({ source: 'migration' }, { id: 'system-user' }, 'acme/connector-custom', 'custom-catalog');
    expect(mockListCatalogContractLogos).not.toHaveBeenCalled();
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-1',
      'Connector',
      { manager_contract: { ...customCatalogContract, embedded: true }, manager_upgrade_strategy: 'latest' },
    );
  });

  it('should fallback to the embedded catalog and fix the catalog id when the catalog is not found in ES', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-2',
      catalog_id: 'ipinfo',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: undefined,
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    expect(mockFindLatestCompatibleCatalogContractByImageName).not.toHaveBeenCalled();
    expect(mockMapContractDtoV0ToContractEntityFields).toHaveBeenCalledWith(expect.objectContaining({ catalogId: 'filigran-catalog' }));
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-2',
      'Connector',
      {
        catalog_id: 'filigran-catalog',
        manager_contract: { catalog_id: 'filigran-catalog', contract_id: 'ipinfo-1.2.3', image: 'opencti/connector-ipinfo' },
        manager_upgrade_strategy: 'latest',
      },
    );
  });

  it('should keep the catalog id when falling back to the embedded catalog it is bound to', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-3',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: undefined,
      manager_upgrade_strategy: 'latest',
    }]);
    await runUp();
    const patch = mockPatchAttribute.mock.calls[0][4];
    expect(patch.catalog_id).toBeUndefined();
    expect(patch.manager_contract).toBeDefined();
  });

  it('should only patch upgrade strategy when the contract snapshot already exists', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-4',
      catalog_id: 'ipinfo',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: { contract_id: 'ipinfo-1.2.3' },
      manager_upgrade_strategy: undefined,
    }]);
    await runUp();
    expect(mockFindCatalogByCatalogId).not.toHaveBeenCalled();
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-4',
      'Connector',
      { manager_upgrade_strategy: 'latest' },
    );
  });

  it('should not patch connectors that already have manager contract and strategy', async () => {
    mockFullEntitiesList.mockResolvedValue([{
      id: 'connector-5',
      catalog_id: 'ipinfo',
      manager_contract_image: 'opencti/connector-ipinfo',
      manager_contract: { contract_id: 'ipinfo-1.2.3' },
      manager_upgrade_strategy: 'latest',
    }]);
    await runUp();
    expect(mockFindCatalogByCatalogId).not.toHaveBeenCalled();
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('should still patch upgrade strategy when the contract is found in no catalog', async () => {
    mockFindLatestCompatibleCatalogContractByImageName.mockResolvedValue(undefined);
    mockFullEntitiesList.mockResolvedValue([
      { id: 'connector-6', catalog_id: 'custom-catalog', manager_contract_image: 'acme/connector-unknown' },
      { id: 'connector-7', catalog_id: 'unknown', manager_contract_image: 'opencti/connector-unknown' },
    ]);
    await runUp();
    expect(mockPatchAttribute).toHaveBeenCalledTimes(2);
    expect(mockPatchAttribute).toHaveBeenCalledWith({ source: 'migration' }, { id: 'system-user' }, 'connector-6', 'Connector', { manager_upgrade_strategy: 'latest' });
    expect(mockPatchAttribute).toHaveBeenCalledWith({ source: 'migration' }, { id: 'system-user' }, 'connector-7', 'Connector', { manager_upgrade_strategy: 'latest' });
    expect(logMigration.error).toHaveBeenCalledWith(expect.stringContaining('connector connector-6 missing contract acme/connector-unknown in catalog custom-catalog'));
    expect(logMigration.error).toHaveBeenCalledWith(expect.stringContaining('connector connector-7 missing contract opencti/connector-unknown in the embedded catalog'));
  });

  it('should log an error and still patch upgrade strategy when the connector has no contract image', async () => {
    mockFullEntitiesList.mockResolvedValue([{ id: 'connector-8', catalog_id: 'custom-catalog' }]);
    await runUp();
    expect(mockFindCatalogByCatalogId).not.toHaveBeenCalled();
    expect(logMigration.error).toHaveBeenCalledWith(expect.stringContaining('connector connector-8 has neither a contract snapshot nor a contract image'));
    expect(mockPatchAttribute).toHaveBeenCalledWith({ source: 'migration' }, { id: 'system-user' }, 'connector-8', 'Connector', { manager_upgrade_strategy: 'latest' });
  });

  it('should log an error and still embed the contract when the logo storage fails', async () => {
    mockStoreCatalogContractLogo.mockResolvedValue({ result: 'failed', logoUri: null, error: new Error('logo upload failed') });
    mockFullEntitiesList.mockResolvedValue([{ id: 'connector-9', catalog_id: 'ipinfo', manager_contract_image: 'opencti/connector-ipinfo' }]);
    await runUp();
    expect(logMigration.error).toHaveBeenCalledWith(expect.stringContaining('failed to store logo into file storage for connector connector-9 (logo upload failed)'));
    expect(mockPatchAttribute.mock.calls[0][4].manager_contract).toBeDefined();
  });
});
