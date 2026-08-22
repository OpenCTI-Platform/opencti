import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { TYPE_LOCK_ERROR } from '../../../src/config/errors';

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
const toPersistableManifestMetadataMock = vi.fn();
const persistCatalogSnapshotMock = vi.fn();
const upsertCatalogManifestMock = vi.fn();
const findCatalogManifestBySourceUriMock = vi.fn();
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

    toPersistableManifestMetadata(...args: unknown[]) {
      return toPersistableManifestMetadataMock(...args);
    }
  }

  return {
    NewManifestAdapter,
    resolveCatalogSource: (...args: unknown[]) => resolveCatalogSourceMock(...args),
  };
});

vi.mock('../../../src/modules/catalog/catalog-repository', () => ({
  persistCatalogSnapshot: (...args: unknown[]) => persistCatalogSnapshotMock(...args),
  upsertCatalogManifest: (...args: unknown[]) => upsertCatalogManifestMock(...args),
  findCatalogManifestBySourceUri: (...args: unknown[]) => findCatalogManifestBySourceUriMock(...args),
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
    toPersistableManifestMetadataMock.mockReturnValue({
      catalogId: 'filigran-catalog-id',
      manifestVersion: 'connector-manifest-7.260728.0-260729083711',
      productVersion: '7.260728.0',
    });
    persistCatalogSnapshotMock.mockResolvedValue(undefined);
    upsertCatalogManifestMock.mockResolvedValue(undefined);
    findCatalogManifestBySourceUriMock.mockResolvedValue(undefined);
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
    expect(upsertCatalogManifestMock).toHaveBeenCalledTimes(1);
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
    expect(upsertCatalogManifestMock).toHaveBeenCalledTimes(2);
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

  it('does not start when feature flag is disabled', async () => {
    isFeatureEnabledMock.mockReturnValue(false);
    const module = await loadManagerModule();

    await module.default.start();

    expect(setIntervalAsyncMock).not.toHaveBeenCalled();
    expect(newFetchMock).not.toHaveBeenCalled();
    expect(logInfoMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager not started (feature flag disabled)');
  });

  it('does not start when manager is disabled by configuration', async () => {
    booleanConfMock.mockReturnValue(false);
    const module = await loadManagerModule();

    await module.default.start();

    expect(setIntervalAsyncMock).not.toHaveBeenCalled();
    expect(newFetchMock).not.toHaveBeenCalled();
    expect(logInfoMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager disabled by configuration');
  });

  it('handles lock contention without warning and logs debug', async () => {
    lockResourcesMock.mockRejectedValue({ name: TYPE_LOCK_ERROR });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, headers: { get: () => 'etag-1' } }));
    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(logDebugMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager refresh already running on another API');
    expect(logWarnMock).not.toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager background refresh failed', expect.anything());
  });

  it('skips HEAD check when source is local', async () => {
    resolveCatalogSourceMock.mockReturnValue({
      source: { kind: 'local', uri: '/tmp/catalog.json' },
      originalUri: '/tmp/catalog.json',
    });
    const headFetch = vi.fn();
    vi.stubGlobal('fetch', headFetch);
    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(headFetch).not.toHaveBeenCalled();
    expect(newFetchMock).toHaveBeenCalledWith({ kind: 'local', uri: '/tmp/catalog.json' }, { signal: expect.any(Object) });
  });

  it('hydrates revision from persisted catalog metadata and skips fetch when remote etag matches', async () => {
    findCatalogManifestBySourceUriMock.mockResolvedValueOnce({
      source_uri: 'https://hub.example/catalog',
      revision: 'etag-from-es',
    });
    const headFetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => 'etag-from-es' },
    });
    vi.stubGlobal('fetch', headFetch);

    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(findCatalogManifestBySourceUriMock).toHaveBeenCalledWith(
      { source: 'catalog_manager' },
      { id: 'system-user' },
      'https://hub.example/catalog',
    );
    expect(newFetchMock).not.toHaveBeenCalled();
    expect(persistCatalogSnapshotMock).not.toHaveBeenCalled();
    expect(module.getCatalogVersionInfo()).toEqual(expect.objectContaining({ status: 'ready', revision: 'etag-from-es' }));
  });

  it('hydrates persisted etag then refreshes and persists when remote etag changed', async () => {
    findCatalogManifestBySourceUriMock.mockResolvedValueOnce({
      source_uri: 'https://hub.example/catalog',
      revision: 'etag-old',
      catalog_id: 'filigran-catalog-id',
    });
    const headFetch = vi.fn().mockResolvedValue({
      ok: true,
      headers: { get: () => 'etag-new' },
    });
    vi.stubGlobal('fetch', headFetch);

    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(findCatalogManifestBySourceUriMock).toHaveBeenCalledTimes(1);
    expect(newFetchMock).toHaveBeenCalledTimes(1);
    expect(persistCatalogSnapshotMock).toHaveBeenCalledWith(
      { source: 'catalog_manager' },
      { id: 'system-user' },
      expect.objectContaining({
        catalogId: 'filigran-catalog-id',
      }),
    );
    expect(upsertCatalogManifestMock).toHaveBeenCalledWith(
      { source: 'catalog_manager' },
      { id: 'system-user' },
      expect.objectContaining({
        source_uri: 'https://hub.example/catalog',
        catalog_id: 'filigran-catalog-id',
        revision: 'etag-new',
      }),
    );
    expect(module.getCatalogVersionInfo()).toEqual(expect.objectContaining({ status: 'ready', revision: 'etag-new' }));
  });

  it('marks status as error and logs timeout details when fetch times out', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, headers: { get: () => null } }));
    newFetchMock.mockRejectedValue({ name: 'AbortError', message: 'Operation timeout', code: 'ABORT_ERR' });
    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(module.getCatalogVersionInfo()).toEqual(expect.objectContaining({ status: 'error' }));
    expect(logWarnMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager request timed out', expect.objectContaining({ timeoutMs: 15000 }));
    expect(logWarnMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager failed to refresh the catalog from configured source', expect.anything());
  });

  it('marks status as error when persistence fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true, headers: { get: () => 'etag-1' } }));
    persistCatalogSnapshotMock.mockRejectedValue(new Error('persist failure'));
    const module = await loadManagerModule();

    module.default.triggerRefreshInBackground();
    await waitAsync();

    expect(module.getCatalogVersionInfo()).toEqual(expect.objectContaining({ status: 'error' }));
    expect(logWarnMock).toHaveBeenCalledWith('[OPENCTI-MODULE] Catalog manager fetched manifest but failed to persist it to ES', expect.anything());
  });

  it('clears scheduler on shutdown when started with interval', async () => {
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
    await module.default.shutdown();

    expect(clearIntervalAsyncMock).toHaveBeenCalledTimes(1);
  });
});
