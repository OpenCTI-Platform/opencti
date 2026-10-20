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
import {
  type GlobalIngestionHealthContext,
  HEALTH_CHECK_REGISTRY,
  type HealthCheckCode,
  type HealthCheckDefinition,
  type RuntimeCheckDefinition,
  type RuntimeData,
} from '../modules/ingestionHealth/ingestionHealth-registry';
import { publishUserAction } from '../listener/UserActionListener';
import type { IngestionHealthFields } from '../modules/ingestionHealth/ingestionHealth-types';
import { IngestionHealthCheckKind } from '../generated/graphql';
import { findRegularlyPingingConnectors, isConnectorStopped } from '../modules/connector/connector-domain';
import { isSyncRunning } from '../domain/connector';
import { isIngestionRunning } from '../modules/ingestion/ingestion-common';

const INGESTION_HEALTH_MANAGER_ENABLED = booleanConf('ingestion_health_manager:enabled', true);
const INGESTION_HEALTH_MANAGER_KEY = conf.get('ingestion_health_manager:lock_key') || 'ingestion_health_manager_lock';
const SCHEDULE_TIME = conf.get('ingestion_health_manager:interval') || 60000; // 1 minute

type IngestionElement = BasicStoreEntity & IngestionHealthFields;

interface IngestionSource<T extends IngestionElement> {
  entityType: string;
  load: (context: AuthContext) => Promise<T[]>;
}

const connectorSource: IngestionSource<CachedConnector> = {
  entityType: ENTITY_TYPE_CONNECTOR,
  // Cached on every node, and refreshed cache after each health write
  load: (context) => getEntitiesListFromCache<CachedConnector>(context, INGESTION_HEALTH_MANAGER_USER, ENTITY_TYPE_CONNECTOR),
};

const feedOrSyncSource = (entityType: string): IngestionSource<IngestionElement & { user_id?: string | null }> => ({
  entityType,
  // Feeds and syncs are not cached
  load: (context) => fullEntitiesList(context, INGESTION_HEALTH_MANAGER_USER, [entityType]),
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

// Stopped on purpose, each type with the rule of the process running it
const isIngestionStopped = (element: IngestionElement & { ingestion_running?: boolean; running?: boolean }) => {
  switch (element.entity_type) {
    case ENTITY_TYPE_CONNECTOR:
      return isConnectorStopped(element);
    case ENTITY_TYPE_SYNC:
      return !isSyncRunning(element);
    default:
      // Feeds
      return !isIngestionRunning(element);
  }
};

const writeIngestionHealth = async <T extends IngestionElement>(context: AuthContext, source: IngestionSource<T>, element: T, patch: IngestionHealthFields) => {
  // Standard update: moves updated_at and emits an update event
  const { element: updatedElement } = await patchAttribute(context, INGESTION_HEALTH_MANAGER_USER, element.internal_id, source.entityType, patch);
  if (source.entityType === ENTITY_TYPE_CONNECTOR) {
    // patchAttribute does not refresh the caches: notify every node, as registerConnector does
    await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, updatedElement, INGESTION_HEALTH_MANAGER_USER);
  }
};

// Reads the values of the runtime checks for a batch of ingestions: one getRuntimeData call per check, whatever the number of ingestions.
// A read failure is not hidden: it rejects, so that an unreachable storage is never read as a missing value.
const loadRuntimeData = async (ingestionIds: string[]): Promise<Map<string, RuntimeData>> => {
  if (ingestionIds.length === 0) {
    return new Map();
  }
  const runtimeChecks = (Object.entries(HEALTH_CHECK_REGISTRY) as [HealthCheckCode, HealthCheckDefinition][])
    .filter((entry): entry is [HealthCheckCode, RuntimeCheckDefinition<unknown>] => entry[1].kind === IngestionHealthCheckKind.Runtime);
  const valuesByCheck = await Promise.all(runtimeChecks.map(([, definition]) => definition.getRuntimeData()));
  return new Map(ingestionIds.map((ingestionId) => {
    const runtimeData = Object.fromEntries(runtimeChecks.map(([code], index) => [code, valuesByCheck[index].get(ingestionId)]));
    return [ingestionId, runtimeData as RuntimeData];
  }));
};

// Stopped on purpose: nothing is evaluated (no checks, no runtime data read) and nothing is reported,
// the stored health, if any, is removed
const clearIngestionHealth = async <T extends IngestionElement>(context: AuthContext, source: IngestionSource<T>, element: T) => {
  if (element.ingestion_health) {
    await writeIngestionHealth(context, source, element, { ingestion_health: null });
  }
};

const evaluateIngestionHealth = async <T extends IngestionElement>(
  context: AuthContext,
  source: IngestionSource<T>,
  element: T,
  periodContext: GlobalIngestionHealthContext,
  runtimeData: RuntimeData,
) => {
  const healthContext = { ...periodContext, runtimeData };
  const checks = computeIngestionHealthChecks(element, healthContext);
  const patch = computeIngestionHealthPatch(element, checks, healthContext);
  if (!patch) {
    return;
  }
  await writeIngestionHealth(context, source, element, patch);
  // Published a health activity event after the write
  // a failed write is retried at the next period and reports the transition then
  const nextHealth = patch.ingestion_health;
  const transition = computeHealthTransition(element.ingestion_health?.status, nextHealth?.status);
  if (transition) {
    await publishUserAction({
      user: INGESTION_HEALTH_MANAGER_USER,
      event_type: 'ingestion_health',
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

  // build required info data
  const users = await getEntitiesMapFromCache<AuthUser>(context, INGESTION_HEALTH_MANAGER_USER, ENTITY_TYPE_USER);
  const isExistingUser = (userId: string) => users.has(userId) || userId in INTERNAL_USERS;
  const pingingConnectors = await findRegularlyPingingConnectors(context, INGESTION_HEALTH_MANAGER_USER);
  const pingingConnectorsIds = new Set(pingingConnectors.map((connector) => connector.internal_id));

  // check the ingestions sources
  for (let sourceIndex = 0; sourceIndex < INGESTION_SOURCES.length; sourceIndex += 1) {
    lock.signal.throwIfAborted();
    const source = INGESTION_SOURCES[sourceIndex];
    const elements = await source.load(context);
    const stoppedElements = elements.filter(isIngestionStopped);
    const activeElements = elements.filter((element) => !isIngestionStopped(element));

    // Stopped: the only place handling them, nothing read, nothing evaluated, nothing reported
    for (let i = 0; i < stoppedElements.length; i += 1) {
      // Outside the try: losing the lock must stop the scan, not be logged as an element failure
      lock.signal.throwIfAborted();
      try {
        await clearIngestionHealth(context, source, stoppedElements[i]);
      } catch (e) {
        logApp.warn('[OPENCTI-MODULE] Ingestion health clear error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', id: stoppedElements[i].internal_id, type: source.entityType });
      }
    }

    // Active
    let runtimeDataByIngestion: Map<string, RuntimeData>;
    try {
      runtimeDataByIngestion = await loadRuntimeData(activeElements.map((element) => element.internal_id));
    } catch (e) {
      logApp.warn('[OPENCTI-MODULE] Ingestion health runtime data read error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', type: source.entityType });
      continue;
    }
    const periodContext = { evaluatedAt: now(), isExistingUser, pingingConnectorsIds };
    for (let i = 0; i < activeElements.length; i += 1) {
      lock.signal.throwIfAborted();
      const element = activeElements[i];
      try {
        await evaluateIngestionHealth(context, source, element, periodContext, runtimeDataByIngestion.get(element.internal_id) ?? {});
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
