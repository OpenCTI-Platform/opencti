import { beforeEach, describe, expect, it, vi } from 'vitest';

const {
  mockFullEntitiesList,
  mockPatchAttribute,
  mockFindCatalogContractsBySlugs,
} = vi.hoisted(() => ({
  mockFullEntitiesList: vi.fn(),
  mockPatchAttribute: vi.fn(),
  mockFindCatalogContractsBySlugs: vi.fn(),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
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
  findCatalogContractsBySlugs: mockFindCatalogContractsBySlugs,
}));

vi.mock('../../../src/__generated__/opencti-manifest.json', () => ({
  default: {
    id: 'filigran-catalog',
    contracts: [
      {
        slug: 'ipinfo',
        container_version: '1.2.3',
        config_schema: { properties: { IPINFO_TOKEN: {}, IPINFO_MAX_TLP: {}, IPINFO_USE_ASN_NAME: {} } },
      },
    ],
  },
}));

import { up } from '../../../src/migrations/1793265832421-keep-managed-connectors-options-order';

const runUp = async () => {
  await new Promise<void>((resolve, reject) => {
    void up((error?: Error) => {
      if (error) reject(error);
      else resolve();
    });
  });
};

const buildConnector = (id: string, slug: string, contractId: string, configSchema: Record<string, unknown>, catalogId = 'filigran-catalog') => ({
  id,
  catalog_id: catalogId,
  manager_contract: { catalog_id: catalogId, slug, contract_id: contractId, title: slug, config_schema: configSchema },
});

describe('migration 1793265832421 managed connectors options order', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockPatchAttribute.mockResolvedValue(undefined);
    mockFindCatalogContractsBySlugs.mockResolvedValue([{
      catalog_id: 'filigran-catalog',
      contract_id: 'misp-2.0.0',
      config_schema: { properties: { MISP_URL: {}, MISP_KEY: {}, MISP_SSL_VERIFY: {} } },
    }]);
  });

  it('should take the order of the options from the catalog contract of the same version', async () => {
    const configSchema = { type: 'object', properties: { MISP_SSL_VERIFY: {}, MISP_URL: {}, MISP_KEY: {} }, required: ['MISP_URL'] };
    mockFullEntitiesList.mockResolvedValue([buildConnector('connector-1', 'misp', 'misp-2.0.0', configSchema)]);
    await runUp();
    expect(mockFindCatalogContractsBySlugs).toHaveBeenCalledWith({ source: 'migration' }, { id: 'system-user' }, ['misp']);
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-1',
      'Connector',
      {
        manager_contract: {
          catalog_id: 'filigran-catalog',
          slug: 'misp',
          contract_id: 'misp-2.0.0',
          title: 'misp',
          config_schema: { ...configSchema, properties_order: ['MISP_URL', 'MISP_KEY', 'MISP_SSL_VERIFY'] },
        },
      },
    );
  });

  it('should fallback to the embedded catalog when the catalogs do not have the contract version', async () => {
    const configSchema = { properties: { IPINFO_USE_ASN_NAME: {}, IPINFO_TOKEN: {}, IPINFO_MAX_TLP: {} } };
    mockFullEntitiesList.mockResolvedValue([buildConnector('connector-2', 'ipinfo', 'ipinfo-1.2.3', configSchema)]);
    await runUp();
    expect(mockPatchAttribute).toHaveBeenCalledWith(
      { source: 'migration' },
      { id: 'system-user' },
      'connector-2',
      'Connector',
      { manager_contract: expect.objectContaining({ config_schema: { ...configSchema, properties_order: ['IPINFO_TOKEN', 'IPINFO_MAX_TLP', 'IPINFO_USE_ASN_NAME'] } }) },
    );
  });

  it('should take the order from the catalog of the connector when two catalogs share a contract version', async () => {
    mockFindCatalogContractsBySlugs.mockResolvedValue([
      { catalog_id: 'filigran-catalog', contract_id: 'misp-2.0.0', config_schema: { properties: { MISP_URL: {}, MISP_KEY: {} } } },
      { catalog_id: 'custom-catalog', contract_id: 'misp-2.0.0', config_schema: { properties: { MISP_KEY: {}, MISP_URL: {} } } },
    ]);
    mockFullEntitiesList.mockResolvedValue([
      buildConnector('connector-filigran', 'misp', 'misp-2.0.0', { properties: { MISP_KEY: {}, MISP_URL: {} } }),
      buildConnector('connector-custom', 'misp', 'misp-2.0.0', { properties: { MISP_URL: {}, MISP_KEY: {} } }, 'custom-catalog'),
    ]);
    await runUp();
    const ordersByConnector = Object.fromEntries(mockPatchAttribute.mock.calls.map(([, , id, , patch]) => [id, patch.manager_contract.config_schema.properties_order]));
    expect(ordersByConnector).toEqual({
      'connector-filigran': ['MISP_URL', 'MISP_KEY'],
      'connector-custom': ['MISP_KEY', 'MISP_URL'],
    });
  });

  it('should not take the order of the embedded catalog for a contract of another catalog', async () => {
    mockFullEntitiesList.mockResolvedValue([
      buildConnector('connector-custom', 'ipinfo', 'ipinfo-1.2.3', { properties: { IPINFO_USE_ASN_NAME: {}, IPINFO_TOKEN: {} } }, 'custom-catalog'),
    ]);
    await runUp();
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });

  it('should leave the connectors whose contract version is unknown or already ordered', async () => {
    mockFullEntitiesList.mockResolvedValue([
      buildConnector('connector-3', 'unknown', 'unknown-1.0.0', { properties: { A: {}, B: {} } }),
      buildConnector('connector-4', 'misp', 'misp-2.0.0', { properties: { MISP_KEY: {}, MISP_URL: {} }, properties_order: ['MISP_URL', 'MISP_KEY'] }),
      { id: 'connector-5', catalog_id: 'filigran-catalog', manager_contract: undefined },
    ]);
    await runUp();
    expect(mockFindCatalogContractsBySlugs).toHaveBeenCalledWith({ source: 'migration' }, { id: 'system-user' }, ['unknown']);
    expect(mockPatchAttribute).not.toHaveBeenCalled();
  });
});
