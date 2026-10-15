import conf, { BUS_TOPICS, INGESTION_HEALTH_FEATURE_FLAG, booleanConf, isFeatureEnabled, logApp } from '../config/conf';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../database/cache';
import { patchAttribute } from '../database/middleware';
import { fullEntitiesList } from '../database/middleware-loader';
import { notify } from '../database/redis';
import { type ManagerDefinition, registerManager } from './managerModule';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER } from '../schema/internalObject';
import type { BasicStoreEntity } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import { executionContext, INGESTION_HEALTH_MANAGER_USER, INTERNAL_USERS } from '../utils/access';
import { now } from '../utils/format';
import type { CachedConnector } from '../modules/connector/connector-types';
import {
  ENTITY_TYPE_INGESTION_CSV,
  ENTITY_TYPE_INGESTION_JSON,
  ENTITY_TYPE_INGESTION_RSS,
  ENTITY_TYPE_INGESTION_TAXII,
  ENTITY_TYPE_INGESTION_TAXII_COLLECTION,
} from '../modules/ingestion/ingestion-types';
import {
  buildHealthTransitionMessage,
  computeHealthTransition,
  computeIngestionHealthChecks,
  computeIngestionHealthPatch,
  HealthTransition,
} from '../modules/ingestionHealth/ingestionHealth-checks';
import { publishUserAction } from '../listener/UserActionListener';
import type { IngestionHealthFields } from '../modules/ingestionHealth/ingestionHealth-types';
import { redisGetRuntimeData } from '../modules/ingestionHealth/ingestionHealthMonitoring-redis';
import { isConnectorStopped } from '../modules/connector/connector-domain';

const INGESTION_HEALTH_MANAGER_ENABLED = booleanConf('ingestion_health_manager:enabled', true);
const INGESTION_HEALTH_MANAGER_KEY = conf.get('ingestion_health_manager:lock_key') || 'ingestion_health_manager_lock';
const SCHEDULE_TIME = conf.get('ingestion_health_manager:interval') || 60000; // 1 minute

type IngestionElement = BasicStoreEntity & IngestionHealthFields;

interface IngestionSource<T extends IngestionElement> {
  entityType: string;
  load: (context: AuthContext) => Promise<T[]>;
  getUserId: (element: T) => string | null | undefined;
  // Connectors authenticate with their own user; feeds and syncs without one run as the system user
  isUserRequired: boolean;
  isEvaluated?: (element: T) => boolean;
  // Sources reporting a heartbeat: its absence is a failure, unless the element is stopped on purpose
  isHeartbeatRequired?: boolean;
  isStopped?: (element: T) => boolean;
}

const connectorSource: IngestionSource<CachedConnector> = {
  entityType: ENTITY_TYPE_CONNECTOR,
  // Cached on every node, and refreshed cache after each health write
  load: (context) => getEntitiesListFromCache<CachedConnector>(context, INGESTION_HEALTH_MANAGER_USER, ENTITY_TYPE_CONNECTOR),
  getUserId: (connector) => connector.connector_user_id,
  isUserRequired: true,
  // Built-ins (feed twins) are not deployed: no process runs them
  isEvaluated: (connector) => !connector.built_in,
  isHeartbeatRequired: true,
  isStopped: isConnectorStopped,
};

const feedOrSyncSource = (entityType: string): IngestionSource<IngestionElement & { user_id?: string | null }> => ({
  entityType,
  // Feeds and syncs are not cached
  load: (context) => fullEntitiesList(context, INGESTION_HEALTH_MANAGER_USER, [entityType]),
  getUserId: (element) => element.user_id,
  isUserRequired: false,
});

const INGESTION_SOURCES = [
  connectorSource,
  feedOrSyncSource(ENTITY_TYPE_INGESTION_RSS),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_CSV),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_JSON),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_TAXII),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_TAXII_COLLECTION),
  feedOrSyncSource(ENTITY_TYPE_SYNC),
] as IngestionSource<IngestionElement>[];

const evaluateIngestionHealth = async <T extends IngestionElement>(
  context: AuthContext,
  source: IngestionSource<T>,
  element: T,
  isExistingUser: (userId: string) => boolean,
) => {
  // Stopped on purpose: not monitored, nothing is read nor checked.
  // No status can be computed then, so a health stored before the stop is removed, without activity event.
  const isStopped = source.isStopped?.(element) ?? false;
  // Runtime data reported by the sources, read per ingestion: a Redis failure only skips this ingestion until the next period
  const runtimeData = isStopped ? {} : await redisGetRuntimeData(element.internal_id);
  const checks = isStopped ? [] : computeIngestionHealthChecks({
    userId: source.getUserId(element),
    isUserRequired: source.isUserRequired,
    isHeartbeatRequired: source.isHeartbeatRequired,
    runtimeData,
  }, isExistingUser);
  const patch = computeIngestionHealthPatch(element, checks, now(), { runtimeData });
  if (!patch) {
    return;
  }
  // Standard update: moves updated_at and emits an update event
  const { element: updatedElement } = await patchAttribute(context, INGESTION_HEALTH_MANAGER_USER, element.internal_id, source.entityType, patch);
  if (source.entityType === ENTITY_TYPE_CONNECTOR) {
    // patchAttribute does not refresh the caches: notify every node, as registerConnector does
    await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElement, INGESTION_HEALTH_MANAGER_USER);
  }
  // Published an health activity event after the write
  // a failed write is retried at the next period and reports the transition then
  const nextHealth = patch.ingestion_health;
  const transition = isStopped ? null : computeHealthTransition(element.ingestion_health?.status, nextHealth?.status);
  if (transition) {
    await publishUserAction({
      user: INGESTION_HEALTH_MANAGER_USER,
      event_type: 'health',
      event_scope: transition,
      event_access: 'administration',
      status: transition === HealthTransition.Recovered ? 'success' : 'error',
      message: buildHealthTransitionMessage(element, transition, nextHealth?.health_checks ?? []),
      context_data: { id: element.internal_id, entity_type: source.entityType, entity_name: element.name },
    });
  }
};

export const ingestionHealthHandler = async (lock: { signal: AbortSignal }) => {
  const context = executionContext('ingestion_health_manager');
  const users = await getEntitiesMapFromCache<AuthUser>(context, INGESTION_HEALTH_MANAGER_USER, ENTITY_TYPE_USER);
  const isExistingUser = (userId: string) => users.has(userId) || userId in INTERNAL_USERS;
  for (let sourceIndex = 0; sourceIndex < INGESTION_SOURCES.length; sourceIndex += 1) {
    lock.signal.throwIfAborted();
    const source = INGESTION_SOURCES[sourceIndex];
    const elements = await source.load(context);
    const evaluatedElements = source.isEvaluated ? elements.filter(source.isEvaluated) : elements;
    for (let i = 0; i < evaluatedElements.length; i += 1) {
      // Outside the try: losing the lock must stop the scan, not be logged as an element failure
      lock.signal.throwIfAborted();
      const element = evaluatedElements[i];
      try {
        await evaluateIngestionHealth(context, source, element, isExistingUser);
      } catch (e) {
        // One broken ingestion must not stop the evaluation of the others, retried at the next period
        logApp.warn('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', id: element.internal_id, type: source.entityType });
      }
    }
  }
};

const INGESTION_HEALTH_MANAGER_DEFINITION: ManagerDefinition = {
  id: 'INGESTION_HEALTH_MANAGER',
  label: 'Ingestion health manager',
  executionContext: 'ingestion_health_manager',
  cronSchedulerHandler: {
    handler: ingestionHealthHandler,
    interval: SCHEDULE_TIME,
    lockKey: INGESTION_HEALTH_MANAGER_KEY,
    lockInHandlerParams: true,
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
