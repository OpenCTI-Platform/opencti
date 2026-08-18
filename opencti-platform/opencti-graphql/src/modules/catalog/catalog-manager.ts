import { clearIntervalAsync, setIntervalAsync, type SetIntervalAsyncTimer } from 'set-interval-async/fixed';
import conf, { booleanConf, logApp } from '../../config/conf';
import { lockResources } from '../../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../../config/errors';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { autoUpgradeManagedConnectors } from '../connector/connector-domain';
import { synchronizeCatalogs } from './sync/catalog-sync-domain';

const CATALOG_MANAGER_ENABLED = booleanConf('app:catalog_manager:enabled', true);
const CATALOG_MANAGER_LOCK_KEY = conf.get('app:catalog_manager:lock_key') || 'catalog_manager_lock';
const CATALOG_MANAGER_INTERVAL = conf.get('app:catalog_manager:interval');

let scheduler: SetIntervalAsyncTimer<[]> | undefined;

export const isCatalogManagerEnabled = () => CATALOG_MANAGER_ENABLED;

const executeScheduledJob = async () => {
  let lock;
  try {
    lock = await lockResources([CATALOG_MANAGER_LOCK_KEY], { retryCount: 0 });
    const context = executionContext('catalog_manager');
    // Sync catalogs to ES
    const syncedCatalogsWithChanges = await synchronizeCatalogs(context, SYSTEM_USER);
    // Apply upgrade strategy.
    // Should be moved another manager maybe (connectorManager).
    // Consider using an event to invert the dependency.
    await autoUpgradeManagedConnectors(context, SYSTEM_USER, syncedCatalogsWithChanges);
  } catch (error: any) {
    if (error?.name === TYPE_LOCK_ERROR) {
      logApp.debug('[OPENCTI-MODULE] Catalog manager refresh already running on another node');
      return;
    }
    throw error;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

const triggerExecuteScheduledJob = () => {
  if (!CATALOG_MANAGER_ENABLED) {
    return;
  }
  void executeScheduledJob().catch((error) => {
    logApp.error('[OPENCTI-MODULE] Catalog manager background refresh failed', { cause: error });
  });
};

const start = async () => {
  if (!CATALOG_MANAGER_ENABLED) {
    logApp.info('[OPENCTI-MODULE] Catalog manager disabled by configuration');
    return;
  }

  triggerExecuteScheduledJob();

  if (CATALOG_MANAGER_INTERVAL && Number(CATALOG_MANAGER_INTERVAL) > 0) {
    scheduler = setIntervalAsync(async () => {
      triggerExecuteScheduledJob();
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
