import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import conf, { booleanConf, isFeatureEnabled, logApp } from '../config/conf';
import { lockResources } from '../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../config/errors';
import { LegacyManifestAdapter, NewManifestAdapter, resolveCatalogSource } from '../modules/catalog/catalog-adapters';
import { getCatalogManagerInternalCache, getCatalogStatus, type CatalogStatus, updateCatalogManagerInternalCache } from '../modules/catalog/catalog-domain';

const DECOUPLING_CONNECTOR_VERSIONS = 'DECOUPLING_CONNECTOR_VERSIONS';

const CATALOG_MANAGER_ENABLED = booleanConf('app:catalog_manager:enabled', true);
const CATALOG_MANAGER_LOCK_KEY = conf.get('app:catalog_manager:lock_key') || 'catalog_manager_lock';
const CATALOG_MANAGER_INTERVAL = conf.get('app:catalog_manager:interval');
const CUSTOM_CATALOG_SOURCE_URI = conf.get('app:catalog_manager:custom_catalog_refresh_endpoint_uri');
const CATALOG_MANAGER_REQUEST_TIMEOUT = conf.get('app:catalog_manager:request_timeout');

let scheduler: SetIntervalAsyncTimer<[]> | undefined;
let currentEtag: string | undefined;

const legacyAdapter = new LegacyManifestAdapter();
const newManifestAdapter = new NewManifestAdapter();

const DEFAULT_CATALOG_MANAGER_REQUEST_TIMEOUT = 15000;

const getCatalogManagerRequestTimeoutMs = (): number => {
  const timeoutMs = Number(CATALOG_MANAGER_REQUEST_TIMEOUT);
  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    return timeoutMs;
  }
  return DEFAULT_CATALOG_MANAGER_REQUEST_TIMEOUT;
};

const createRequestTimeoutSignal = (): AbortSignal => AbortSignal.timeout(getCatalogManagerRequestTimeoutMs());

const isCatalogRequestTimeout = (error: unknown): boolean => {
  if (!error || typeof error !== 'object') {
    return false;
  }

  const err = error as { name?: string; message?: string; code?: string };
  const name = err.name ?? '';
  const message = (err.message ?? '').toLowerCase();
  const code = err.code ?? '';

  return name === 'TimeoutError'
    || (name === 'AbortError' && message.includes('timeout'))
    || message.includes('timed out')
    || code === 'ABORT_ERR';
};

const setCatalogStatusWithoutReplacingSnapshot = (status: CatalogStatus) => {
  updateCatalogManagerInternalCache(undefined, status, true);
};

const refreshCatalogInternal = async () => {
  const existingStatus = getCatalogStatus();
  if (existingStatus !== 'loading') {
    setCatalogStatusWithoutReplacingSnapshot('loading');
  }

  const sourceConfig = resolveCatalogSource(CUSTOM_CATALOG_SOURCE_URI).source;
  const shouldCheckEtag = sourceConfig.kind === 'remote';
  let nextEtag: string | undefined;

  try {
    if (shouldCheckEtag) {
      logApp.info('[OPENCTI-MODULE] Catalog manager checking remote manifest via HEAD', { uri: sourceConfig.uri });
      const headResponse = await fetch(sourceConfig.uri, { method: 'HEAD', signal: createRequestTimeoutSignal() });
      if (headResponse.ok) {
        nextEtag = headResponse.headers.get('etag') ?? undefined;
        if (nextEtag && currentEtag && nextEtag === currentEtag) {
          logApp.info('[OPENCTI-MODULE] Catalog manager skipping fetch, remote manifest unchanged (ETag match)', { etag: currentEtag });
          updateCatalogManagerInternalCache(undefined, 'ready', true);
          return;
        }
      }
    }

    logApp.info(`[OPENCTI-MODULE] Catalog manager fetching manifest from ${sourceConfig.kind} source`, { uri: sourceConfig.uri });
    const rawManifest = await newManifestAdapter.fetch(sourceConfig, { signal: createRequestTimeoutSignal() });

    if (!isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
      return;
    }

    const internalCatalog = newManifestAdapter.toInternalCatalog(rawManifest);
    updateCatalogManagerInternalCache(internalCatalog, 'ready');

    if (shouldCheckEtag && nextEtag) {
      currentEtag = nextEtag;
    }
  } catch (error) {
    if (isCatalogRequestTimeout(error)) {
      logApp.warn('[OPENCTI-MODULE] Catalog manager request timed out', {
        timeoutMs: getCatalogManagerRequestTimeoutMs(),
        source: sourceConfig,
      });
    }

    logApp.warn('[OPENCTI-MODULE] Catalog manager failed to refresh the catalog from configured source', { cause: error });

    if (getCatalogManagerInternalCache()) {
      logApp.info('[OPENCTI-MODULE] Catalog manager keeps existing snapshot; no embedded fallback needed');
      updateCatalogManagerInternalCache(undefined, 'error', true);
      return;
    }

    try {
      logApp.info('[OPENCTI-MODULE] Catalog manager will fallback to embedded legacy manifest');
      logApp.info('[OPENCTI-MODULE] Catalog manager falling back to embedded legacy manifest');
      const legacyRaw = await legacyAdapter.fetch({ kind: 'local', uri: 'embedded' });
      const legacyInternal = legacyAdapter.toInternalCatalog(legacyRaw);
      updateCatalogManagerInternalCache(legacyInternal, 'ready');
    } catch (legacyError) {
      logApp.warn('[OPENCTI-MODULE] Catalog manager failed to load embedded legacy manifest fallback', { cause: legacyError });
      updateCatalogManagerInternalCache(undefined, 'error');
    }
  }
};

const refreshCatalog = async () => {
  let lock;
  try {
    lock = await lockResources([CATALOG_MANAGER_LOCK_KEY], { retryCount: 0 });
    await refreshCatalogInternal();
  } catch (error: any) {
    if (error?.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Catalog manager refresh already running on another API');
      return;
    }
    throw error;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

const isDecouplingEnabled = () => CATALOG_MANAGER_ENABLED && isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS);

const triggerRefreshInBackground = () => {
  void refreshCatalog().catch((error) => {
    logApp.warn('[OPENCTI-MODULE] Catalog manager background refresh failed', { cause: error });
  });
};

const start = async () => {
  if (!isDecouplingEnabled()) {
    logApp.info('[OPENCTI-MODULE] Catalog manager not started (disabled by configuration or feature flag)');
    return;
  }

  triggerRefreshInBackground();

  if (CATALOG_MANAGER_INTERVAL && Number(CATALOG_MANAGER_INTERVAL) > 0) {
    scheduler = setIntervalAsync(async () => {
      triggerRefreshInBackground();
    }, Number(CATALOG_MANAGER_INTERVAL));
    logApp.info(`[OPENCTI-MODULE] Catalog manager scheduled every ${Number(CATALOG_MANAGER_INTERVAL)}ms`);
  } else {
    logApp.info('[OPENCTI-MODULE] Catalog manager configured for startup-only refresh');
  }
};

const shutdown = async () => {
  if (scheduler) {
    await clearIntervalAsync(scheduler);
    scheduler = undefined;
  }
};

export default {
  start,
  shutdown,
};
