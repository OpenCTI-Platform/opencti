import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';

const TYPE_LOCK_ERROR_VALUE = 'LOCK_ERROR';

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
const legacyFetchMock = vi.fn();
const legacyToInternalCatalogMock = vi.fn();
const newFetchMock = vi.fn();
const newToInternalCatalogMock = vi.fn();
const getCatalogManagerInternalCacheMock = vi.fn();
const getCatalogStatusMock = vi.fn();
const updateCatalogManagerInternalCacheMock = vi.fn();

vi.mock('set-interval-async/fixed', () => ({
  setIntervalAsync: (...args: unknown[]) => setIntervalAsyncMock(...args),
  clearIntervalAsync: (...args: unknown[]) => clearIntervalAsyncMock(...args),
}));

vi.mock('../../../src/config/conf', () => ({
  default: {
    get: (...args: unknown[]) => confGetMock(...args),
  },
  booleanConf: (...args: unknown[]) => booleanConfMock(...args),
  isFeatureEnabled: (...args: unknown[]) => isFeatureEnabledMock(...args),
  logApp: {
    info: (...args: unknown[]) => logInfoMock(...args),
    warn: (...args: unknown[]) => logWarnMock(...args),
    debug: (...args: unknown[]) => logDebugMock(...args),
  },
}));

vi.mock('../../../src/lock/master-lock', () => ({
  lockResources: (...args: unknown[]) => lockResourcesMock(...args),
}));

vi.mock('../../../src/config/errors', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/errors')>();
  return {
    ...actual,
    TYPE_LOCK_ERROR: TYPE_LOCK_ERROR_VALUE,
  };
});

vi.mock('../../../src/modules/catalog/catalog-adapters', () => {
  class LegacyManifestAdapter {
    fetch(...args: unknown[]) {
      return legacyFetchMock(...args);
    }

    toInternalCatalog(...args: unknown[]) {
      return legacyToInternalCatalogMock(...args);
    }
  }

  class NewManifestAdapter {
    fetch(...args: unknown[]) {
      return newFetchMock(...args);
    }

    toInternalCatalog(...args: unknown[]) {
      return newToInternalCatalogMock(...args);
    }
  }

  return {
    LegacyManifestAdapter,
    NewManifestAdapter,
    resolveCatalogSource: (...args: unknown[]) => resolveCatalogSourceMock(...args),
  };
});

vi.mock('../../../src/modules/catalog/catalog-domain', () => ({
  getCatalogManagerInternalCache: (...args: unknown[]) => getCatalogManagerInternalCacheMock(...args),
  getCatalogStatus: (...args: unknown[]) => getCatalogStatusMock(...args),
  updateCatalogManagerInternalCache: (...args: unknown[]) => updateCatalogManagerInternalCacheMock(...args),
}));

const waitAsync = () => new Promise<void>((resolve) => {
  setImmediate(() => resolve());
});

const loadManagerModule = async () => {
  vi.resetModules();
  const { default: manager } = await import('../../../src/manager/catalogManager');
  return manager;
};

describe('catalogManager', () => {
  const lockUnlockMock = vi.fn();
  const timerRef = { id: 'timer' };

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
      source: { kind: 'remote', uri: 'https://hub.example/octi/6.8.13/connector/manifests' },
      originalUri: 'https://hub.example/octi/6.8.13/connector/manifests',
    });

    lockResourcesMock.mockResolvedValue({ unlock: lockUnlockMock });

    getCatalogStatusMock.mockReturnValue('ready');
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);

    newFetchMock.mockResolvedValue({ id: 'catalog' });
    newToInternalCatalogMock.mockReturnValue({ definitions: [] });
    legacyFetchMock.mockResolvedValue([{ id: 'legacy' }]);
    legacyToInternalCatalogMock.mockReturnValue({ definitions: [{ id: 'legacy' }] });

    setIntervalAsyncMock.mockReturnValue(timerRef);
    clearIntervalAsyncMock.mockResolvedValue(undefined);

    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false,
      headers: { get: () => null },
    }));
  });

  afterAll(() => {
    vi.unstubAllGlobals();
  });

  it('does not start when decoupling feature flag is disabled', async () => {
    isFeatureEnabledMock.mockReturnValue(false);
    const manager = await loadManagerModule();

    await manager.start();
    await waitAsync();

    expect(lockResourcesMock).not.toHaveBeenCalled();
    expect(setIntervalAsyncMock).not.toHaveBeenCalled();
  });

  it('loads embedded fallback when catalog manager is disabled by config', async () => {
    booleanConfMock.mockReturnValue(false);
    const manager = await loadManagerModule();

    await manager.start();

    expect(legacyFetchMock).toHaveBeenCalledWith({ kind: 'local', uri: 'embedded' });
    expect(updateCatalogManagerInternalCacheMock).toHaveBeenCalledWith(
      { definitions: [{ id: 'legacy' }] },
      'ready',
      false,
      expect.any(String),
    );
    expect(setIntervalAsyncMock).not.toHaveBeenCalled();
  });

  it('schedules periodic refresh when interval is positive', async () => {
    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:catalog_manager:lock_key') return 'catalog_manager_lock';
      if (key === 'app:catalog_manager:interval') return 30000;
      if (key === 'app:catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      if (key === 'app:catalog_manager:request_timeout') return 15000;
      return undefined;
    });
    const manager = await loadManagerModule();

    await manager.start();

    expect(setIntervalAsyncMock).toHaveBeenCalledTimes(1);
  });

  it('does startup-only refresh when interval is not set', async () => {
    const manager = await loadManagerModule();

    await manager.start();
    await waitAsync();

    expect(setIntervalAsyncMock).not.toHaveBeenCalled();
    expect(lockResourcesMock).toHaveBeenCalledTimes(1);
  });

  it('skips fetch when remote ETag is unchanged', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => 'etag-1' },
    });
    vi.stubGlobal('fetch', fetchMock);

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();
    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(newFetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('updates internal cache on successful remote refresh', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => 'etag-42' },
    });
    vi.stubGlobal('fetch', fetchMock);

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(newFetchMock).toHaveBeenCalledWith(
      { kind: 'remote', uri: 'https://hub.example/octi/6.8.13/connector/manifests' },
      { signal: expect.any(AbortSignal) },
    );
    expect(updateCatalogManagerInternalCacheMock).toHaveBeenCalledWith(
      { definitions: [] },
      'ready',
      false,
      'etag-42',
    );
  });

  it('returns early after fetch when feature is disabled during refresh', async () => {
    isFeatureEnabledMock.mockImplementationOnce(() => true).mockImplementationOnce(() => false);
    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(newFetchMock).toHaveBeenCalledTimes(1);
    expect(updateCatalogManagerInternalCacheMock).toHaveBeenCalledWith(undefined, 'loading', true);
    expect(updateCatalogManagerInternalCacheMock).not.toHaveBeenCalledWith(
      { definitions: [] },
      'ready',
      false,
      expect.anything(),
    );
  });

  it('keeps existing snapshot and sets error when refresh fails', async () => {
    newFetchMock.mockRejectedValue(new Error('network failed'));
    getCatalogManagerInternalCacheMock.mockReturnValue({ definitions: [{ id: 'existing' }] });

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(updateCatalogManagerInternalCacheMock).toHaveBeenCalledWith(undefined, 'error', true);
    expect(legacyFetchMock).not.toHaveBeenCalled();
  });

  it('falls back to embedded legacy manifest when refresh fails and cache is empty', async () => {
    newFetchMock.mockRejectedValue(new Error('network failed'));
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(legacyFetchMock).toHaveBeenCalledWith({ kind: 'local', uri: 'embedded' });
    expect(updateCatalogManagerInternalCacheMock).toHaveBeenCalledWith(
      { definitions: [{ id: 'legacy' }] },
      'ready',
      false,
      expect.any(String),
    );
  });

  it('sets error when both refresh and fallback fail', async () => {
    newFetchMock.mockRejectedValue(new Error('network failed'));
    legacyFetchMock.mockRejectedValue(new Error('embedded failed'));

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(updateCatalogManagerInternalCacheMock).toHaveBeenLastCalledWith(undefined, 'error');
  });

  it('swallows lock conflict errors', async () => {
    lockResourcesMock.mockRejectedValue({ name: TYPE_LOCK_ERROR_VALUE });

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(logDebugMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager refresh already running on another API');
    expect(newFetchMock).not.toHaveBeenCalled();
  });

  it('logs timeout warning when refresh request times out', async () => {
    newFetchMock.mockRejectedValue({ name: 'TimeoutError' });

    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(logWarnMock).toHaveBeenCalledWith(
      '[OPENCTI-MODULE] Catalog manager request timed out',
      expect.objectContaining({ timeoutMs: 15000 }),
    );
  });

  it('always unlocks resource after refresh attempt', async () => {
    const manager = await loadManagerModule();

    manager.triggerRefreshInBackground();
    await waitAsync();

    expect(lockUnlockMock).toHaveBeenCalledTimes(1);
  });

  it('clears scheduled task on shutdown', async () => {
    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:catalog_manager:lock_key') return 'catalog_manager_lock';
      if (key === 'app:catalog_manager:interval') return 30000;
      if (key === 'app:catalog_manager:custom_catalog_refresh_endpoint_uri') return undefined;
      if (key === 'app:catalog_manager:request_timeout') return 15000;
      return undefined;
    });

    const manager = await loadManagerModule();

    await manager.start();
    await manager.shutdown();

    expect(clearIntervalAsyncMock).toHaveBeenCalledWith(timerRef);
  });
});
