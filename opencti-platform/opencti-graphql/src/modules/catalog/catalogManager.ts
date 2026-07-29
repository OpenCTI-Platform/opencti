import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import { createHash } from 'node:crypto';
import conf, { booleanConf, isFeatureEnabled, logApp } from '../../config/conf';
import { lockResources } from '../../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../../config/errors';
import { NewManifestAdapter, resolveCatalogSource } from './catalog-adapters';
import { persistCatalogSnapshot } from './catalog-repository';
import { DECOUPLING_CONNECTOR_VERSIONS } from './catalog-constants';
import { executionContext, SYSTEM_USER } from '../../utils/access';

const CATALOG_MANAGER_ENABLED = booleanConf('app:catalog_manager:enabled', true);
const CATALOG_MANAGER_LOCK_KEY = conf.get('app:catalog_manager:lock_key') || 'catalog_manager_lock';
const CATALOG_MANAGER_INTERVAL = conf.get('app:catalog_manager:interval');
const CUSTOM_CATALOG_SOURCE_URI = conf.get('app:catalog_manager:custom_catalog_refresh_endpoint_uri');
const CATALOG_MANAGER_REQUEST_TIMEOUT = conf.get('app:catalog_manager:request_timeout');

let scheduler: SetIntervalAsyncTimer<[]> | undefined;
let currentEtag: string | undefined;
let managerCatalogStatus: 'loading' | 'ready' | 'error' = 'loading';
let managerCatalogRevision: string | null = null;
let managerCatalogUpdatedAt: string | null = null;

const newManifestAdapter = new NewManifestAdapter();

const DEFAULT_CATALOG_MANAGER_REQUEST_TIMEOUT = 15000;

export const isCatalogManagerEnabled = () => CATALOG_MANAGER_ENABLED;

const setCatalogVersionInfo = (
  status: 'loading' | 'ready' | 'error',
  revision?: string | null,
) => {
  managerCatalogStatus = status;
  if (revision !== undefined) {
    managerCatalogRevision = revision;
  }
  managerCatalogUpdatedAt = new Date().toISOString();
};

export const getCatalogVersionInfo = () => {
  if (!isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS) || !isCatalogManagerEnabled()) {
    return {
      status: 'ready' as const,
      revision: null,
      updated_at: null,
    };
  }

  return {
    status: managerCatalogStatus,
    revision: managerCatalogRevision,
    updated_at: managerCatalogUpdatedAt,
  };
};

const getCatalogManagerRequestTimeoutMs = (): number => {
  const timeoutMs = Number(CATALOG_MANAGER_REQUEST_TIMEOUT);
  if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
    return timeoutMs;
  }
  return DEFAULT_CATALOG_MANAGER_REQUEST_TIMEOUT;
};

const createRequestTimeoutSignal = (): AbortSignal => AbortSignal.timeout(getCatalogManagerRequestTimeoutMs());

const computeCatalogRevision = (rawManifest: unknown, etag?: string): string => {
  if (etag) {
    return etag;
  }
  return createHash('sha256').update(JSON.stringify(rawManifest)).digest('hex');
};

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

const refreshCatalogInternal = async () => {
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
          setCatalogVersionInfo('ready', currentEtag);
          logApp.info('[OPENCTI-MODULE] Catalog manager skipping fetch, remote manifest unchanged (ETag match)', { etag: currentEtag });
          return;
        }
      }
    }

    logApp.info(`[OPENCTI-MODULE] Catalog manager fetching manifest from ${sourceConfig.kind} source`, { uri: sourceConfig.uri });
    const rawManifest = await newManifestAdapter.fetch(sourceConfig, { signal: createRequestTimeoutSignal() });

    if (!isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
      return;
    }

    const persistableContracts = newManifestAdapter.toPersistableContracts(rawManifest);
    const revision = computeCatalogRevision(rawManifest, nextEtag);

    // NEW — persist before anything else observes this cycle as "done". If this
    // throws, we fall into the catch block below with currentEtag/in-memory cache
    // still at their last-good values, so the next tick naturally retries instead
    // of silently treating a half-applied update as current.
    try {
      await persistCatalogSnapshot(executionContext('catalog_manager'), SYSTEM_USER, { allContracts: persistableContracts });
    } catch (persistError) {
      setCatalogVersionInfo('error');
      logApp.warn('[OPENCTI-MODULE] Catalog manager fetched manifest but failed to persist it to ES', { cause: persistError });
      throw persistError;
    }

    logApp.info('[OPENCTI-MODULE] Catalog manager persisted catalog snapshot', { revision });

    if (shouldCheckEtag && nextEtag) {
      currentEtag = nextEtag;
    }
    setCatalogVersionInfo('ready', revision);
  } catch (error) {
    setCatalogVersionInfo('error');
    if (isCatalogRequestTimeout(error)) {
      logApp.warn('[OPENCTI-MODULE] Catalog manager request timed out', {
        timeoutMs: getCatalogManagerRequestTimeoutMs(),
        source: sourceConfig,
      });
    }

    logApp.warn('[OPENCTI-MODULE] Catalog manager failed to refresh the catalog from configured source', { cause: error });
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
  if (!isDecouplingEnabled()) return;
  void refreshCatalog().catch((error) => {
    logApp.warn('[OPENCTI-MODULE] Catalog manager background refresh failed', { cause: error });
  });
};

const start = async () => {
  if (!isFeatureEnabled(DECOUPLING_CONNECTOR_VERSIONS)) {
    logApp.info('[OPENCTI-MODULE] Catalog manager not started (feature flag disabled)');
    return;
  }

  if (!CATALOG_MANAGER_ENABLED) {
    logApp.info('[OPENCTI-MODULE] Catalog manager disabled by configuration');
    return;
  }

  setCatalogVersionInfo('loading');

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
  triggerRefreshInBackground,
};
