import conf, { booleanConf } from '../../config/conf';
import { executionContext, SYSTEM_USER } from '../../utils/access';
import { autoUpgradeManagedConnectors } from '../connector/connector-domain';
import { synchronizeCatalogs } from './sync/catalog-sync-domain';
import { registerManager, type ManagerDefinition } from '../../manager/managerModule';

const CATALOG_MANAGER_ID = 'CATALOG_MANAGER';
const CATALOG_MANAGER_LABEL = 'Catalog Manager';
const CATALOG_MANAGER_CONTEXT = 'catalog_manager';
const CATALOG_MANAGER_ENABLED = booleanConf('catalog_manager:enabled', true);
const CATALOG_MANAGER_LOCK_KEY = conf.get('catalog_manager:lock_key') ?? 'catalog_manager_lock';
const CATALOG_MANAGER_INTERVAL = conf.get('catalog_manager:interval') ?? 60_000;

export const isCatalogManagerEnabled = () => CATALOG_MANAGER_ENABLED;

const catalogManagerHandler = async () => {
  const context = executionContext('catalog_manager');
  // Sync catalogs to ES
  const syncedCatalogsWithChanges = await synchronizeCatalogs(context, SYSTEM_USER);
  // Apply upgrade strategy.
  // Should be moved another manager maybe (connectorManager).
  // Consider using an event to invert the dependency.
  await autoUpgradeManagedConnectors(context, SYSTEM_USER, syncedCatalogsWithChanges);
};

const CATALOG_MANAGER_DEFINITION: ManagerDefinition = {
  id: CATALOG_MANAGER_ID,
  label: CATALOG_MANAGER_LABEL,
  executionContext: CATALOG_MANAGER_CONTEXT,
  enabledByConfig: CATALOG_MANAGER_ENABLED,
  enabled(): boolean {
    return this.enabledByConfig && !!CATALOG_MANAGER_LOCK_KEY;
  },
  enabledToStart(): boolean {
    return this.enabledByConfig && !!CATALOG_MANAGER_LOCK_KEY;
  },
  enterpriseEditionOnly: false,
  cronSchedulerHandler: {
    handler: catalogManagerHandler,
    interval: CATALOG_MANAGER_INTERVAL,
    lockKey: CATALOG_MANAGER_LOCK_KEY,
  },
};

// Automatically register manager on start.
registerManager(CATALOG_MANAGER_DEFINITION);
