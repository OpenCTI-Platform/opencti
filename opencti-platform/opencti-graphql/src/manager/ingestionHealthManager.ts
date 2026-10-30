import conf, { BUS_TOPICS, INGESTION_HEALTH_FEATURE_FLAG, booleanConf, isFeatureEnabled, logApp } from '../config/conf';
import { getEntitiesListFromCache, getEntitiesMapFromCache } from '../database/cache';
import { patchAttribute } from '../database/middleware';
import { fullEntitiesList } from '../database/middleware-loader';
import { notify } from '../database/redis';
import { type ManagerDefinition, registerManager } from './managerModule';
import { ABSTRACT_INTERNAL_OBJECT } from '../schema/general';
import { ENTITY_TYPE_CONNECTOR, ENTITY_TYPE_SYNC, ENTITY_TYPE_USER } from '../schema/internalObject';
import { getResolvedIngestionHealthSettings } from '../modules/ingestionHealth/ingestionHealth-domain';
import type { BasicStoreEntity } from '../types/store';
import type { AuthContext, AuthUser } from '../types/user';
import { executionContext, INGESTION_HEALTH_MANAGER_USER, INTERNAL_USERS, isUserHasCapability } from '../utils/access';
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
  buildIngestionHealthContext,
  computeHealthTransition,
  computeIngestionHealthChecks,
  computeIngestionHealthPatch,
  isRuntimeCheckEnabled,
  markHealthNotified,
} from '../modules/ingestionHealth/ingestionHealth-checks';
import {
  getIngestorUserId,
  type GlobalIngestionHealthContext,
  HEALTH_CHECK_REGISTRY,
  type HealthCheckCode,
  type HealthCheckUser,
  type RuntimeCheck,
  type RuntimeData,
  type SourceIngestionHealthContext,
} from '../modules/ingestionHealth/ingestionHealth-registry';
import { publishUserAction } from '../listener/UserActionListener';
import { HealthTransition, type IngestionHealthFields } from '../modules/ingestionHealth/ingestionHealth-types';
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

// Built-in connectors (feed twins) are not deployed: no process runs them, nothing to evaluate
const isConnectorNotBuiltIn = (element: { built_in?: boolean }) => !element.built_in;

const connectorSource: IngestionSource<CachedConnector> = {
  entityType: ENTITY_TYPE_CONNECTOR,
  // Cached on every node, and refreshed cache after each health write
  load: async (context) => {
    const connectors = await getEntitiesListFromCache<CachedConnector>(context, INGESTION_HEALTH_MANAGER_USER, ENTITY_TYPE_CONNECTOR);
    return connectors.filter(isConnectorNotBuiltIn);
  },
};

const feedOrSyncSource = (entityType: string): IngestionSource<IngestionElement & { user_id?: string | null }> => ({
  entityType,
  // Feeds and syncs are not cached
  load: (context) => fullEntitiesList(context, INGESTION_HEALTH_MANAGER_USER, [entityType]),
});

const INGESTION_SOURCES: IngestionSource<IngestionElement>[] = [
  connectorSource,
  feedOrSyncSource(ENTITY_TYPE_INGESTION_RSS),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_CSV),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_JSON),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_TAXII),
  feedOrSyncSource(ENTITY_TYPE_INGESTION_TAXII_COLLECTION),
  feedOrSyncSource(ENTITY_TYPE_SYNC),
];

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
// Each check only reads the ingestions it is enabled for, and is not called when there is none.
// A read failure is not hidden: it rejects, so that an unreachable storage is never read as a missing value.
const loadRuntimeData = async (
  elements: IngestionElement[],
  globalContext: GlobalIngestionHealthContext,
): Promise<Map<string, RuntimeData>> => {
  // A disabled check is not evaluated: its values are not read
  const runtimeChecks = Object.entries(HEALTH_CHECK_REGISTRY)
    .filter((entry): entry is [HealthCheckCode, RuntimeCheck] => entry[1].kind === IngestionHealthCheckKind.Runtime)
    .filter(([code]) => !globalContext.disabledHealthChecks?.includes(code));
  const valuesByCheck = await Promise.all(runtimeChecks.map(([, definition]) => {
    const enabledIds = elements.filter((element) => definition.isEnabled(element, globalContext)).map((element) => element.internal_id);
    return enabledIds.length > 0 ? definition.getRuntimeData(enabledIds) : new Map<string, unknown>();
  }));
  return new Map(elements.map((element) => {
    const runtimeData = Object.fromEntries(runtimeChecks.map(([code], index) => [code, valuesByCheck[index].get(element.internal_id)]));
    return [element.internal_id, runtimeData];
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
  sourceContext: SourceIngestionHealthContext,
) => {
  const healthContext = buildIngestionHealthContext(element, sourceContext);
  const checks = computeIngestionHealthChecks(element, healthContext);
  const patch = computeIngestionHealthPatch(element, checks, healthContext);

  // The notification is evaluated at every period, even when the health did not change: it is deferred until the status is stable
  const nextHealth = patch ? patch.ingestion_health : element.ingestion_health;
  const transition = computeHealthTransition(nextHealth, sourceContext.evaluatedAt, sourceContext.notificationDelay);
  if (transition && nextHealth) {
    try {
      await publishUserAction({
        user: INGESTION_HEALTH_MANAGER_USER,
        event_type: 'ingestion_health',
        event_scope: transition,
        event_access: 'administration',
        status: transition === HealthTransition.Recovered ? 'success' : 'error',
        message: buildHealthTransitionMessage(element, transition, nextHealth.health_checks ?? []),
        context_data: { id: element.internal_id, entity_type: source.entityType, entity_name: element.name },
      });
    } catch (error) {
      // Not published: the health is written without the marker, the transition is published again at the next period
      if (patch) {
        await writeIngestionHealth(context, source, element, patch);
      }
      throw error;
    }
    // Published first, so the health and the marker go in a single write (one update event, one cache notification).
    // A failed write publishes the transition again at the next period: a duplicate event rather than a lost one
    await writeIngestionHealth(context, source, element, { ingestion_health: markHealthNotified(nextHealth, sourceContext.evaluatedAt) });
    return;
  }
  if (patch) {
    await writeIngestionHealth(context, source, element, patch);
  }
};

export const ingestionHealthHandler = async (lock: { signal: AbortSignal }) => {
  const context = executionContext('ingestion_health_manager');

  // build required info data
  const users = await getEntitiesMapFromCache<AuthUser>(context, INGESTION_HEALTH_MANAGER_USER, ENTITY_TYPE_USER);
  // The user an ingestion runs as: undefined when no user is set or it does not exist anymore
  const resolveUser = (element: IngestionElement): HealthCheckUser | undefined => {
    const userId = getIngestorUserId(element);
    if (!userId) {
      return undefined;
    }
    const internal = userId in INTERNAL_USERS;
    const authUser = internal ? INTERNAL_USERS[userId] : users.get(userId); // Ensure userID exist in user list or INTERNAL_USERS
    return authUser
      ? { internal, user_service_account: authUser.user_service_account === true, hasCapability: (capability) => isUserHasCapability(authUser, capability) }
      : undefined;
  };
  const { notification_delay: notificationDelay, disabled_health_checks: disabledHealthChecks } = await getResolvedIngestionHealthSettings(context, INGESTION_HEALTH_MANAGER_USER);
  const pingingConnectors = await findRegularlyPingingConnectors(context, INGESTION_HEALTH_MANAGER_USER);
  const pingingConnectorsIds = new Set(pingingConnectors.map((connector) => connector.internal_id));

  // The disabled checks are known before the read: the ingestions depending on them only are not read, nor skipped on a read failure
  const globalContext: GlobalIngestionHealthContext = { pingingConnectorsIds, disabledHealthChecks };

  // check the ingestions sources: the active ones are evaluated together, once the runtime data is read for all of them
  const activeIngestions: { source: IngestionSource<IngestionElement>; element: IngestionElement }[] = [];
  for (let sourceIndex = 0; sourceIndex < INGESTION_SOURCES.length; sourceIndex += 1) {
    lock.signal.throwIfAborted();
    const source = INGESTION_SOURCES[sourceIndex];
    const elements = await source.load(context);
    const stoppedElements: IngestionElement[] = [];
    const activeElements: IngestionElement[] = [];
    elements.forEach((element) => (isIngestionStopped(element) ? stoppedElements : activeElements).push(element));

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
    activeIngestions.push(...activeElements.map((element) => ({ source, element })));
  }

  // Read once per period, for the ingestions enabling a runtime check only: nothing is read when there is none
  const runtimeElements = activeIngestions
    .map(({ element }) => element)
    .filter((element) => isRuntimeCheckEnabled(element, globalContext));
  const runtimeIngestionIds = new Set(runtimeElements.map((element) => element.internal_id));
  let runtimeDataByIngestion: Map<string, RuntimeData> | undefined;
  try {
    runtimeDataByIngestion = await loadRuntimeData(runtimeElements, globalContext);
  } catch (e) {
    // Not read as a missing value: the ingestions needing it are skipped until the next period, the others are still evaluated
    logApp.warn('[OPENCTI-MODULE] Ingestion health runtime data read error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER' });
  }
  // Right after the read: the values read are judged against the moment they were read at
  const periodContext = { ...globalContext, evaluatedAt: now(), notificationDelay };

  // Active
  for (let i = 0; i < activeIngestions.length; i += 1) {
    lock.signal.throwIfAborted();
    const { source, element } = activeIngestions[i];
    if (!runtimeDataByIngestion && runtimeIngestionIds.has(element.internal_id)) {
      continue;
    }
    try {
      const runtimeData = runtimeDataByIngestion?.get(element.internal_id) ?? {};
      await evaluateIngestionHealth(context, source, element, { ...periodContext, runtimeData, user: resolveUser(element) });
    } catch (e) {
      // One broken ingestion must not stop the evaluation of the others, retried at the next period
      logApp.warn('[OPENCTI-MODULE] Ingestion health evaluation error', { cause: e, manager: 'INGESTION_HEALTH_MANAGER', id: element.internal_id, type: source.entityType });
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
