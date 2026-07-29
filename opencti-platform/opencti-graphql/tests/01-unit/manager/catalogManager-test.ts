import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const setIntervalAsyncMock = vi.fn();
const clearIntervalAsyncMock = vi.fn();

const confGetMock = vi.fn();
const booleanConfMock = vi.fn();
const isFeatureEnabledMock = vi.fn();
const logInfoMock = vi.fn();
const logWarnMock = vi.fn();
const logDebugMock = vi.fn();

const lockResourcesMock = vi.fn();
const resolveCatalogSourceMock = vi.fn();
const newFetchMock = vi.fn();
const toPersistableContractsMock = vi.fn();
const persistCatalogSnapshotMock = vi.fn();
const executionContextMock = vi.fn();

vi.mock('set-interval-async/fixed', () => ({
  setIntervalAsync: (...args: unknown[]) => setIntervalAsyncMock(...args),
  clearIntervalAsync: (...args: unknown[]) => clearIntervalAsyncMock(...args),
}));

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      get: (...args: unknown[]) => confGetMock(...args),
    },
    booleanConf: (...args: unknown[]) => booleanConfMock(...args),
    isFeatureEnabled: (...args: unknown[]) => isFeatureEnabledMock(...args),
    logApp: {
      ...actual.logApp,
      info: (...args: unknown[]) => logInfoMock(...args),
      warn: (...args: unknown[]) => logWarnMock(...args),
      debug: (...args: unknown[]) => logDebugMock(...args),
    },
  };
});

vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: (...args: unknown[]) => lockResourcesMock(...args),
}));

vi.mock('../../../src/modules/catalog/catalog-adapters', () => {
  class NewManifestAdapter {
    fetch(...args: unknown[]) {
      return newFetchMock(...args);
    }

    toPersistableContracts(...args: unknown[]) {
      return toPersistableContractsMock(...args);
    }
  }

  return {
    NewManifestAdapter,
    resolveCatalogSource: (...args: unknown[]) => resolveCatalogSourceMock(...args),
  };
});

vi.mock('../../../src/modules/catalog/catalog-repository', () => ({
  persistCatalogSnapshot: (...args: unknown[]) => persistCatalogSnapshotMock(...args),
}));

vi.mock('../../../src/utils/access', () => ({
  executionContext: (...args: unknown[]) => executionContextMock(...args),
  SYSTEM_USER: { id: 'system-user' },
}));

const waitAsync = () => new Promise<void>((resolve) => {
  setImmediate(() => resolve());
});

const loadManagerModule = async () => {
  vi.resetModules();
  return import('../../../src/modules/catalog/catalogManager');
};

describe('catalogManager', () => {
  const unlockMock = vi.fn();

  beforeEach(() => {
    vi.clearAllMocks();

    booleanConfMock.mockReturnValue(true);
    isFeatureEnabledMock.mockReturnValue(true);

    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:catalog_manager:lock_key') return 'catalog_manager_lock';
      if (key === 'app:catalog_manager:interval') return 0;
      if (key === 'app:catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      if (key === 'app:catalog_manager:request_timeout') return 15000;
      return undefined;
    });

    resolveCatalogSourceMock.mockReturnValue({
      source: { kind: 'remote', uri: 'https://hub.example/catalog' },
      originalUri: 'https://hub.example/catalog',
    });

    lockResourcesMock.mockResolvedValue({ unlock: unlockMock });

    newFetchMock.mockResolvedValue({ id: 'manifest-1', contracts: [] });
    toPersistableContractsMock.mockReturnValue([{ slug: 'ipinfo', version: '1.0.0' }]);
    persistCatalogSnapshotMock.mockResolvedValue(undefined);
    executionContextMock.mockReturnValue({ source: 'catalog_manager' });

    setIntervalAsyncMock.mockReturnValue({ id: 'timer' });
    clearIntervalAsyncMock.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('skips fetch/update cycle when remote ETag is unchanged', async () => {
    const headFetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => 'etag-1' },
    });
    vi.stubGlobal('fetch', headFetch);

    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(headFetch).toHaveBeenCalledTimes(2);
    expect(newFetchMock).toHaveBeenCalledTimes(1);
    expect(persistCatalogSnapshotMock).toHaveBeenCalledTimes(1);
    expect(module.getCatalogVersionInfo()).toEqual(expect.objectContaining({ status: 'ready', revision: 'etag-1' }));
  });

  it('fetches and persists again when remote ETag changed', async () => {
    const headFetch = vi.fn()
      .mockResolvedValueOnce({ ok: true, headers: { get: () => 'etag-1' } })
      .mockResolvedValueOnce({ ok: true, headers: { get: () => 'etag-2' } });
    vi.stubGlobal('fetch', headFetch);

    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(newFetchMock).toHaveBeenCalledTimes(2);
    expect(persistCatalogSnapshotMock).toHaveBeenCalledTimes(2);
    expect(module.getCatalogVersionInfo()).toEqual(expect.objectContaining({ status: 'ready', revision: 'etag-2' }));
  });

  it('schedules periodic refresh when interval is configured', async () => {
    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:catalog_manager:lock_key') return 'catalog_manager_lock';
      if (key === 'app:catalog_manager:interval') return 30000;
      if (key === 'app:catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      if (key === 'app:catalog_manager:request_timeout') return 15000;
      return undefined;
    });

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, headers: { get: () => 'etag-1' } }));

    const module = await loadManagerModule();

    await module.default.start();

    expect(setIntervalAsyncMock).toHaveBeenCalledTimes(1);
    expect(setIntervalAsyncMock).toHaveBeenCalledWith(expect.any(Function), 30000);
  });
});
