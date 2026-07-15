import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const lockResourcesMock = vi.fn();
const updateCatalogManagerInternalCacheMock = vi.fn();
const getCatalogManagerInternalCacheMock = vi.fn();
const getCatalogStatusMock = vi.fn();
const isFeatureEnabledMock = vi.fn();
const booleanConfMock = vi.fn();
const confGetMock = vi.fn();
const fetchMock = vi.fn();

vi.stubGlobal('fetch', fetchMock);

vi.mock('../../../../src/lock/master-lock', () => ({
  lockResources: lockResourcesMock,
}));

vi.mock('../../../../src/modules/catalog/catalog-domain', () => ({
  updateCatalogManagerInternalCache: updateCatalogManagerInternalCacheMock,
  getCatalogManagerInternalCache: getCatalogManagerInternalCacheMock,
  getCatalogStatus: getCatalogStatusMock,
}));

vi.mock('../../../../src/config/conf', async () => {
  const actual = await vi.importActual<typeof import('../../../../src/config/conf')>('../../../../src/config/conf');
  return {
    ...actual,
    default: {
      get: confGetMock,
    },
    booleanConf: booleanConfMock,
    isFeatureEnabled: isFeatureEnabledMock,
    logApp: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
  };
});

describe('catalogManager', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    booleanConfMock.mockReturnValue(true);
    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:catalog_manager:lock_key') return 'catalog_manager_lock';
      if (key === 'app:catalog_manager:interval') return null;
      if (key === 'app:catalog_manager:custom_catalog_refresh_endpoint_uri') return './connector-catalog.json.local';
      return undefined;
    });
    isFeatureEnabledMock.mockImplementation((flag: string) => flag === 'DECOUPLING_CONNECTOR_VERSIONS');
    getCatalogStatusMock.mockReturnValue('ready');
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);
    lockResourcesMock.mockResolvedValue({ unlock: vi.fn() });

    fetchMock.mockResolvedValue({
      ok: true,
      headers: { get: () => 'etag-v1' },
      json: async () => ({
        id: 'catalog-v2',
        name: 'Catalog v2',
        description: 'Fixture for manager tests',
        manifest_schema_version: '16.0.0',
        contracts: [],
      }),
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('acquires the configured lock before refresh', async () => {
    const manager = (await import('../../../../src/manager/catalogManager')).default;

    await manager.start();

    expect(lockResourcesMock).toHaveBeenCalledWith(['catalog_manager_lock'], { retryCount: 0 });
  });

  it('does not refresh when feature flag is disabled', async () => {
    isFeatureEnabledMock.mockReturnValue(false);
    const manager = (await import('../../../../src/manager/catalogManager')).default;

    await manager.start();

    expect(lockResourcesMock).not.toHaveBeenCalled();
  });
});
