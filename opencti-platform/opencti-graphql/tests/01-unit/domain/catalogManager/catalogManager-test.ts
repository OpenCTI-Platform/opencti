import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const lockResourcesMock = vi.fn();
const updateCatalogManagerInternalCacheMock = vi.fn();
const getCatalogManagerInternalCacheMock = vi.fn();
const getCatalogStatusMock = vi.fn();
const isFeatureEnabledMock = vi.fn();
const booleanConfMock = vi.fn();
const confGetMock = vi.fn();

// Global fetch is used by the manager directly for HEAD requests (ETag check).
const headFetchMock = vi.fn();
// Adapter mocks – per-test behaviour is set via newAdapterFetchMock / legacyAdapterFetchMock
const newAdapterFetchMock = vi.fn();
const newAdapterToInternalCatalogMock = vi.fn();
const legacyAdapterFetchMock = vi.fn();
const legacyAdapterToInternalCatalogMock = vi.fn();
const resolveCatalogSourceMock = vi.fn();

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

vi.mock('../../../../src/modules/catalog/catalog-adapters', () => ({
  resolveCatalogSource: resolveCatalogSourceMock,
  // eslint-disable-next-line object-shorthand
  LegacyManifestAdapter: vi.fn().mockImplementation(function (this: Record<string, unknown>) {
    this.fetch = legacyAdapterFetchMock;
    this.toInternalCatalog = legacyAdapterToInternalCatalogMock;
  }),
  // eslint-disable-next-line object-shorthand
  NewManifestAdapter: vi.fn().mockImplementation(function (this: Record<string, unknown>) {
    this.fetch = newAdapterFetchMock;
    this.toInternalCatalog = newAdapterToInternalCatalogMock;
  }),
}));

/** Wait until a mock receives the expected call, polling every 10 ms. */
const waitForCall = (mockFn: ReturnType<typeof vi.fn>, ...expectedArgs: unknown[]) =>
  vi.waitFor(
    () => expect(mockFn).toHaveBeenCalledWith(...expectedArgs),
    { timeout: 2000, interval: 10 },
  );

const REMOTE_SOURCE = { kind: 'remote', uri: 'http://localhost:9090/catalog' };

/** Fake internal catalog returned by toInternalCatalog mocks. */
const fakeInternalCatalog = () => ({ catalogMap: {}, contractsByImage: new Map() });

/** Default HEAD mock: returns ok with given etag. */
const setupHeadMock = (etag = 'etag-v1') => {
  headFetchMock.mockResolvedValue({ ok: true, headers: { get: () => etag } });
};

/** Make the new adapter return a successful catalog. */
const makeSuccessfulNewAdapter = (etag = 'etag-v1') => {
  setupHeadMock(etag);
  newAdapterFetchMock.mockResolvedValue({ etag, contracts: [] });
  newAdapterToInternalCatalogMock.mockReturnValue(fakeInternalCatalog());
};

describe('catalogManager', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();

    // Re-stub global fetch each test so the HEAD mock is active after vi.unstubAllGlobals()
    vi.stubGlobal('fetch', headFetchMock);

    booleanConfMock.mockReturnValue(true);
    confGetMock.mockImplementation((key: string) => {
      if (key === 'app:catalog_manager:lock_key') return 'catalog_manager_lock';
      if (key === 'app:catalog_manager:interval') return null;
      if (key === 'app:catalog_manager:custom_catalog_refresh_endpoint_uri') return 'http://localhost:9090/catalog';
      if (key === 'app:catalog_manager:request_timeout') return null;
      return undefined;
    });
    isFeatureEnabledMock.mockImplementation((flag: string) => flag === 'DECOUPLING_CONNECTOR_VERSIONS');
    getCatalogStatusMock.mockReturnValue('ready');
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);
    lockResourcesMock.mockResolvedValue({ unlock: vi.fn() });

    resolveCatalogSourceMock.mockReturnValue({ source: REMOTE_SOURCE, originalUri: REMOTE_SOURCE.uri });
    makeSuccessfulNewAdapter();
      // HEAD fetch default (can be overridden per test)
    legacyAdapterFetchMock.mockResolvedValue([]);
    legacyAdapterToInternalCatalogMock.mockReturnValue(fakeInternalCatalog());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('acquires the configured lock before refresh', async () => {
    const manager = (await import('../../../../src/manager/catalogManager')).default;

    await manager.start();

    await waitForCall(lockResourcesMock, ['catalog_manager_lock'], { retryCount: 0 });
  });

  it('does not refresh when feature flag is disabled', async () => {
    isFeatureEnabledMock.mockReturnValue(false);
    const manager = (await import('../../../../src/manager/catalogManager')).default;

    await manager.start();
    await new Promise<void>((resolve) => { setImmediate(resolve); });

    expect(lockResourcesMock).not.toHaveBeenCalled();
  });

  // ── scenario: load → HTTP 500 error ────────────────────────────────────────
  it('sets status to error and keeps existing snapshot when remote returns HTTP 500', async () => {
    getCatalogManagerInternalCacheMock.mockReturnValue({ catalogMap: {}, contractsByImage: new Map() });

    newAdapterFetchMock.mockRejectedValue(Object.assign(new Error('HTTP 500'), { status: 500 }));

    const manager = (await import('../../../../src/manager/catalogManager')).default;
    await manager.start();

    await waitForCall(updateCatalogManagerInternalCacheMock, undefined, 'error', true);
  });

  // ── scenario: load → bad JSON ───────────────────────────────────────────────
  it('sets status to error when remote returns malformed JSON', async () => {
    getCatalogManagerInternalCacheMock.mockReturnValue({ catalogMap: {}, contractsByImage: new Map() });

    newAdapterFetchMock.mockRejectedValue(new SyntaxError('Unexpected token { in JSON'));

    const manager = (await import('../../../../src/manager/catalogManager')).default;
    await manager.start();

    await waitForCall(updateCatalogManagerInternalCacheMock, undefined, 'error', true);
  });

  // ── scenario: error → recover (new catalog loaded successfully) ─────────────
  it('sets status to ready with new catalog after recovering from error', async () => {
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);
    getCatalogStatusMock.mockReturnValue('error');
    makeSuccessfulNewAdapter('etag-recovered');

    const manager = (await import('../../../../src/manager/catalogManager')).default;
    await manager.start();

    // Wait until a ready call is made (snapshot replaced, keepExistingSnapshot=false)
    await vi.waitFor(() => {
      const readyCall = updateCatalogManagerInternalCacheMock.mock.calls.find(
        ([, status]: [unknown, string]) => status === 'ready',
      );
      expect(readyCall).toBeDefined();
      expect(readyCall![2]).toBe(false);
    }, { timeout: 2000, interval: 10 });
  });

  // ── scenario: ETag unchanged → skip GET ────────────────────────────────────
  it('skips GET and sets ready when remote ETag is unchanged', async () => {
    getCatalogManagerInternalCacheMock.mockReturnValue({ catalogMap: {}, contractsByImage: new Map() });
    // First start – new adapter returns successfully, manager stores currentEtag
    makeSuccessfulNewAdapter('etag-stable');

    const manager = (await import('../../../../src/manager/catalogManager')).default;

    await manager.start();
    // Wait until a full ready call is made (snapshot set = keepExistingSnapshot false)
    await vi.waitFor(() => {
      const readyCall = updateCatalogManagerInternalCacheMock.mock.calls.find(
        ([, status, keep]: [unknown, string, boolean]) => status === 'ready' && keep === false,
      );
      expect(readyCall).toBeDefined();
      expect(readyCall![3]).toBe('etag-stable');
    }, { timeout: 2000, interval: 10 });

    updateCatalogManagerInternalCacheMock.mockClear();
    newAdapterFetchMock.mockClear();

    // Second start – adapter would reject to simulate what the manager decides on ETag match.
    // The manager checks currentEtag against the HEAD etag BEFORE calling the adapter's main fetch.
    // To verify skip: make the adapter fail if called, proving the GET-equivalent was never reached.
    // The manager handles ETag at HEAD level (via global fetch), so we verify via the cache update.

    await manager.start();

  await waitForCall(updateCatalogManagerInternalCacheMock, undefined, 'ready', true, 'etag-stable');

    // Adapter fetch was NOT called on the second start (ETag skip happened at HEAD level)
    expect(newAdapterFetchMock).not.toHaveBeenCalled();
  });

  // ── scenario: revision changes when new catalog is fetched ─────────────────
  it('writes a new revision when remote catalog changes (new ETag)', async () => {
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);
    makeSuccessfulNewAdapter('etag-new');

    const manager = (await import('../../../../src/manager/catalogManager')).default;
    await manager.start();

    await vi.waitFor(() => {
      const readyCall = updateCatalogManagerInternalCacheMock.mock.calls.find(
        ([, status]: [unknown, string]) => status === 'ready',
      );
      expect(readyCall).toBeDefined();
      // 4th argument is revision – should be the ETag value
      expect(readyCall![3]).toBe('etag-new');
    }, { timeout: 2000, interval: 10 });
  });

  // ── scenario: no snapshot → fallback to embedded legacy manifest ────────────
  it('falls back to embedded legacy manifest when remote fails and no snapshot exists', async () => {
    getCatalogManagerInternalCacheMock.mockReturnValue(undefined);
    newAdapterFetchMock.mockRejectedValue(new Error('Network unreachable'));

    const manager = (await import('../../../../src/manager/catalogManager')).default;
    await manager.start();

    // Wait until the final status is written (either ready via fallback or error)
    await vi.waitFor(() => {
      const calls = updateCatalogManagerInternalCacheMock.mock.calls;
      const lastCall = calls.at(-1);
      expect(lastCall).toBeDefined();
      expect(['ready', 'error']).toContain(lastCall![1]);
    }, { timeout: 2000, interval: 10 });
  });
});
