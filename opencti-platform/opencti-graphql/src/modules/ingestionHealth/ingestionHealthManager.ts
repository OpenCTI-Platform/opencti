import conf, { BUS_TOPICS, INGESTION_HEALTH_FEATURE_FLAG, booleanConf, isFeatureEnabled, logApp } from '../../config/conf';
import { getEntitiesMapFromCache } from '../../database/cache';
import { elReplace } from '../../database/engine';
import { fullEntitiesList } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { type ManagerDefinition, registerManager } from '../../manager/managerModule';
import { ABSTRACT_INTERNAL_OBJECT } from '../../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_USER } from '../../schema/internalObject';
import type { AuthContext, AuthUser } from '../../types/user';
import { executionContext, INTERNAL_USERS, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import type { BasicStoreEntityConnector } from '../connector/connector-types';
import { computeConnectorHealthChecks, computeIngestionHealthPatch } from './ingestionHealth-checks';

const INGESTION_HEALTH_MANAGER_ENABLED = booleanConf('ingestion_health_manager:enabled', true);
const INGESTION_HEALTH_MANAGER_KEY = conf.get('ingestion_health_manager:lock_key') || 'ingestion_health_manager_lock';
const SCHEDULE_TIME = conf.get('ingestion_health_manager:interval') || 60000; // 1 minute

const evaluateConnectorHealth = async (context: AuthContext, connector: BasicStoreEntityConnector, isExistingUser: (userId: string) => boolean) => {
  const checks = computeConnectorHealthChecks(connector, isExistingUser);
  const patch = computeIngestionHealthPatch(connector, checks, now());
  if (!patch) {
    return;
  }
  // Direct write: an entity update would move updated_at and emit a stream event
  await elReplace(context, connector._index, connector.internal_id, { doc: patch });
  // Refresh the connectors cache of every node
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, { ...connector, ...patch }, SYSTEM_USER);
};

export const ingestionHealthHandler = async () => {
  const context = executionContext('ingestion_health_manager');
  const connectors = await fullEntitiesList<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR]);
  const users = await getEntitiesMapFromCache<AuthUser>(context, SYSTEM_USER, ENTITY_TYPE_USER);
  const isExistingUser = (userId: string) => users.has(userId) || userId in INTERNAL_USERS;
  // Built-ins (feed twins) are not deployed: no process runs them
  const deployedConnectors = connectors.filter((connector) => !connector.built_in);
  for (let i = 0; i < deployedConnectors.length; i += 1) {
    const connector = deployedConnectors[i];
    try {
      await evaluateConnectorHealth(context, connector, isExistingUser);
    } catch (e) {
      // One broken connector must not stop the evaluation of the others, retried at the next period
      logApp.error('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', id: connector.internal_id });
    }
  }
  logApp.debug('[OPENCTI-MODULE] Ingestion health manager process complete', { count: deployedConnectors.length });
};

const INGESTION_HEALTH_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'INGESTION_HEALTH_MANAGER',
  label: 'Ingestion health manager',
  executionContext: 'ingestion_health_manager',
  cronSchedulerHandler: {
    handler: ingestionHealthHandler,
    interval: SCHEDULE_TIME,
    lockKey: INGESTION_HEALTH_MANAGER_KEY,
  },
  enabledByConfig: INGESTION_HEALTH_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

if (isFeatureEnabled(INGESTION_HEALTH_FEATURE_FLAG)) {
  registerManager(INGESTION_HEALTH_MANAGER_DEFINITION);
}
