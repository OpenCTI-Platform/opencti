import { beforeEach, describe, expect, it, vi } from 'vitest';
import { pathToFileURL } from 'node:url';

const {
  mockFetchSourceCatalog,
  mockFetchSourceCatalogRevisionHint,
  mockFindCatalogBySourceUri,
  mockFindCatalogByCatalogId,
  mockFindCatalogContractsByCatalogId,
  mockFindCatalogs,
  mockInsertCatalogContracts,
  mockUpdateCatalogContracts,
  mockDeleteCatalogContracts,
  mockUpsertCatalog,
  mockDeleteCatalogs,
  mockListCatalogContractLogos,
  mockConfGet,
  featureFlagState,
} = vi.hoisted(() => ({
  mockFetchSourceCatalog: vi.fn(),
  mockFetchSourceCatalogRevisionHint: vi.fn(),
  mockFindCatalogBySourceUri: vi.fn(),
  mockFindCatalogByCatalogId: vi.fn(),
  mockFindCatalogContractsByCatalogId: vi.fn(),
  mockFindCatalogs: vi.fn(),
  mockInsertCatalogContracts: vi.fn(),
  mockUpdateCatalogContracts: vi.fn(),
  mockDeleteCatalogContracts: vi.fn(),
  mockUpsertCatalog: vi.fn(),
  mockDeleteCatalogs: vi.fn(),
  mockListCatalogContractLogos: vi.fn(),
  mockConfGet: vi.fn((key: string): any => {
    if (key === 'redis:ca') return [];
    if (key === 'redis:use_ssl') return false;
    return undefined;
  }),
  featureFlagState: { value: false },
}));

vi.mock('../../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: mockConfGet,
    },
    isFeatureEnabled: vi.fn(() => featureFlagState.value),
    PLATFORM_VERSION: '7.2.0',
  };
});

vi.mock('../../../../src/utils/access', () => ({
  SYSTEM_USER: { id: 'system-user' },
}));

vi.mock('../../../../src/modules/catalog/sync/catalog-sync-source-gateway', () => ({
  fetchSourceCatalog: mockFetchSourceCatalog,
  fetchSourceCatalogRevisionHint: mockFetchSourceCatalogRevisionHint,
}));

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findCatalogBySourceUri: mockFindCatalogBySourceUri,
  findCatalogByCatalogId: mockFindCatalogByCatalogId,
  findCatalogContractsByCatalogId: mockFindCatalogContractsByCatalogId,
  findCatalogs: mockFindCatalogs,
  insertCatalogContracts: mockInsertCatalogContracts,
  updateCatalogContracts: mockUpdateCatalogContracts,
  deleteCatalogContracts: mockDeleteCatalogContracts,
  upsertCatalog: mockUpsertCatalog,
  deleteCatalogs: mockDeleteCatalogs,
}));

vi.mock('../../../../src/modules/catalog/catalog-logo-storage', () => ({
  listCatalogContractLogos: mockListCatalogContractLogos,
  computeCatalogContractLogoUploadOperation: vi.fn(() => ({ result: 'no-logo', logoUri: null })),
  uploadCatalogContractLogoOperation: vi.fn(async () => ({ result: 'success' })),
}));

vi.mock('../../../../src/modules/catalog/catalog-logger', () => ({
  logCatalog: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock('../../../../src/schema/identifier', () => ({
  idGenFromData: vi.fn((entityType: string, data: Record<string, string>) => `${entityType}-${Object.values(data).join('-')}-internal`),
  generateStandardId: vi.fn((entityType: string, data: Record<string, string>) => `${entityType}-${Object.values(data).join('-')}-standard`),
}));

import { synchronizeCatalogs } from '../../../../src/modules/catalog/sync/catalog-sync-domain';

const buildSourceCatalog = (id: string) => ({
  id,
  name: `Catalog ${id}`,
  description: 'desc',
  product_version: '7.2.0',
  manifest_version: null,
  manifest_schema_version: '0' as const,
  contracts: [],
});

describe('catalog-sync-domain', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    featureFlagState.value = false;
    mockConfGet.mockImplementation((key: string) => {
      if (key === 'redis:ca') return [];
      if (key === 'redis:use_ssl') return false;
      if (key === 'app:custom_catalogs') return [];
      if (key === 'catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      if (key === 'xtm:xtmhub_url') return undefined;
      return undefined;
    });
    mockFetchSourceCatalogRevisionHint.mockResolvedValue(undefined);
    mockFindCatalogBySourceUri.mockResolvedValue(undefined);
    mockFindCatalogByCatalogId.mockResolvedValue(undefined);
    mockFindCatalogContractsByCatalogId.mockResolvedValue(new Map());
    mockFindCatalogs.mockResolvedValue([]);
    mockListCatalogContractLogos.mockResolvedValue(new Set());
    mockInsertCatalogContracts.mockResolvedValue(undefined);
    mockUpdateCatalogContracts.mockResolvedValue(undefined);
    mockDeleteCatalogContracts.mockResolvedValue(undefined);
    mockUpsertCatalog.mockResolvedValue(undefined);
    mockDeleteCatalogs.mockResolvedValue(undefined);
  });

  it('should use embedded source by default', async () => {
    mockFetchSourceCatalog.mockResolvedValue(buildSourceCatalog('embedded-catalog'));
    const result = await synchronizeCatalogs({ source: 'test' } as any, { id: 'user-1' } as any);
    expect(result).toEqual(['embedded-catalog']);
    expect(mockFetchSourceCatalog).toHaveBeenCalledWith({ kind: 'embedded', uri: 'embedded' }, undefined);
    expect(mockFindCatalogs).toHaveBeenCalled();
  });

  it('should include custom sources and deduplicate by uri', async () => {
    mockConfGet.mockImplementation((key: string) => {
      if (key === 'redis:ca') return [];
      if (key === 'redis:use_ssl') return false;
      if (key === 'catalog_manager:custom_catalog_refresh_endpoint_uri') return 'https://catalog.example.org/custom.json';
      if (key === 'app:custom_catalogs') return ['https://catalog.example.org/custom.json', '/tmp/custom-catalog.json'];
      if (key === 'xtm:xtmhub_url') return undefined;
      return undefined;
    });
    mockFetchSourceCatalog.mockImplementation(async (source: { uri: string }) => buildSourceCatalog(source.uri));
    const result = await synchronizeCatalogs({ source: 'test' } as any, { id: 'user-1' } as any);
    const calledSources = mockFetchSourceCatalog.mock.calls.map((call) => call[0]);
    expect(calledSources).toEqual([
      { kind: 'embedded', uri: 'embedded' },
      { kind: 'remote', uri: 'https://catalog.example.org/custom.json' },
      { kind: 'local', filepath: '/tmp/custom-catalog.json', uri: pathToFileURL('/tmp/custom-catalog.json').toString() },
    ]);
    expect(result).toHaveLength(3);
  });

  it('should ignore custom catalog manager endpoint when decoupling feature is disabled', async () => {
    mockConfGet.mockImplementation((key: string) => {
      if (key === 'redis:ca') return [];
      if (key === 'redis:use_ssl') return false;
      if (key === 'catalog_manager:custom_catalog_refresh_endpoint_uri') return 'https://catalog.example.org/custom.json';
      if (key === 'app:custom_catalogs') return [];
      if (key === 'xtm:xtmhub_url') return 'https://xtm.example.org';
      return undefined;
    });
    mockFetchSourceCatalog.mockResolvedValue(buildSourceCatalog('embedded-catalog'));
    await synchronizeCatalogs({ source: 'test' } as any, { id: 'user-1' } as any);
    expect(mockFetchSourceCatalog).toHaveBeenCalledTimes(1);
    expect(mockFetchSourceCatalog).toHaveBeenCalledWith({ kind: 'embedded', uri: 'embedded' }, undefined);
  });

  it('should use custom catalog manager endpoint instead of xtm hub source when decoupling feature is enabled', async () => {
    featureFlagState.value = true;
    mockConfGet.mockImplementation((key: string) => {
      if (key === 'redis:ca') return [];
      if (key === 'redis:use_ssl') return false;
      if (key === 'catalog_manager:custom_catalog_refresh_endpoint_uri') return 'https://catalog.example.org/custom.json';
      if (key === 'app:custom_catalogs') return [];
      if (key === 'xtm:xtmhub_url') return 'https://xtm.example.org';
      return undefined;
    });
    mockFetchSourceCatalog.mockResolvedValue(buildSourceCatalog('custom-catalog'));
    await synchronizeCatalogs({ source: 'test' } as any, { id: 'user-1' } as any);
    expect(mockFetchSourceCatalog).toHaveBeenCalledTimes(1);
    expect(mockFetchSourceCatalog).toHaveBeenCalledWith({ kind: 'remote', uri: 'https://catalog.example.org/custom.json' }, undefined);
  });

  it('should fallback to embedded when remote decoupling source fails before first persistence', async () => {
    featureFlagState.value = true;
    mockConfGet.mockImplementation((key: string) => {
      if (key === 'redis:ca') return [];
      if (key === 'redis:use_ssl') return false;
      if (key === 'xtm:xtmhub_url') return 'https://xtm.example.org';
      if (key === 'app:custom_catalogs') return [];
      if (key === 'catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      return undefined;
    });
    mockFetchSourceCatalog.mockImplementation(async (source: { kind: string }) => {
      if (source.kind === 'remote') {
        throw new Error('remote unavailable');
      }
      return buildSourceCatalog('embedded-fallback');
    });
    const result = await synchronizeCatalogs({ source: 'test' } as any, { id: 'user-1' } as any);
    expect(result).toEqual(['embedded-fallback']);
    expect(mockFetchSourceCatalog.mock.calls[0][0].kind).toBe('remote');
    expect(mockFetchSourceCatalog.mock.calls[1][0]).toEqual({ kind: 'embedded', uri: 'embedded' });
  });

  it('should skip obsolete catalog cleanup when at least one source sync fails', async () => {
    mockConfGet.mockImplementation((key: string) => {
      if (key === 'redis:ca') return [];
      if (key === 'redis:use_ssl') return false;
      if (key === 'catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      if (key === 'app:custom_catalogs') return ['/tmp/custom-catalog.json'];
      if (key === 'xtm:xtmhub_url') return undefined;
      return undefined;
    });
    mockFetchSourceCatalog.mockImplementation(async (source: { kind: string }) => {
      if (source.kind === 'local') {
        throw new Error('local source failure');
      }
      return buildSourceCatalog('embedded-catalog');
    });
    const result = await synchronizeCatalogs({ source: 'test' } as any, { id: 'user-1' } as any);
    expect(result).toEqual(['embedded-catalog']);
    expect(mockFindCatalogs).not.toHaveBeenCalled();
    expect(mockDeleteCatalogs).not.toHaveBeenCalled();
  });
});
