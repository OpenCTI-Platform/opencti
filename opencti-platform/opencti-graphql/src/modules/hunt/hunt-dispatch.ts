import { findByIds } from './hunt-loaders';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity, BasicStoreEntityMarkingDefinition } from '../../types/store';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { withHuntLock } from './hunt-lock';
import { getEntitiesMapFromCache } from '../../database/cache';
import { completeConnector } from '../../database/repository';
import { pushToConnector } from '../../database/rabbitmq';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { fullEntitiesList } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import { createWork, deleteWork } from '../../domain/work';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { ENTITY_TYPE_MARKING_DEFINITION } from '../../schema/stixMetaObject';
import { CONNECTOR_INTERNAL_HUNT } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { HUNT_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import {
  type BasicStoreEntityHunt,
  HUNT_PLATFORM_INTERNET,
  HUNT_TYPE_INDICATORS,
  HUNT_TYPE_INFRASTRUCTURE,
  RELATION_HUNT_SOURCES,
  RELATION_HUNT_TARGETS,
  RELATION_HUNT_TECHNIQUES,
} from './hunt-types';
import { type HuntIoc, isDisclosableByHunt, resolveHuntIocSet } from './hunt-iocs';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_IOC_VERDICT_PENDING,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_QUEUED,
  type HuntIocResult,
  HUNT_RUN_TRIGGER_MANUAL,
  HUNT_RUN_TRIGGER_PREVIEW,
} from './huntRun/huntRun-types';
import { clampInteger, HUNT_CONFIG, HUNT_DEFAULT_MAX_RESULTS, huntExpectedObservables, normalizeNativeQueries, parseHuntFilterGroup } from './hunt-utils';
import { HUNT_MESSAGES, type HuntMessage, huntMessage, type HuntMessageValues, renderHuntMessage } from './hunt-messages';

export interface HuntConnectorTarget {
  connector: BasicStoreEntityConnector;
  securityPlatform: BasicStoreEntitySecurityPlatform | null;
}

/**
 * Active hunt connectors, completed with their liveness (a connector pings every minute).
 * Read from the database, never from the entity cache: a ping refreshes updated_at in the database only, so the cached
 * copy of a live connector looks dead 5 minutes after the cache was last loaded.
 */
export const listHuntConnectors = async (context: AuthContext, onlyAlive = true): Promise<BasicStoreEntityConnector[]> => {
  const connectors = await fullEntitiesList<BasicStoreEntityConnector>(context, SYSTEM_USER, [ENTITY_TYPE_CONNECTOR], {
    filters: { mode: FilterMode.And, filters: [{ key: ['connector_type'], values: [CONNECTOR_INTERNAL_HUNT] }], filterGroups: [] },
    noFiltersChecking: true,
  });
  return connectors
    .map((connector) => completeConnector(connector) as BasicStoreEntityConnector)
    .filter((connector) => !onlyAlive || connector.active === true);
};

export const huntConnectorPlatform = (connector: BasicStoreEntityConnector): string | null => {
  if (connector.hunt_platform) {
    return connector.hunt_platform;
  }
  const scope = completeConnector(connector)?.connector_scope ?? [];
  return scope.length > 0 ? String(scope[0]).toLowerCase() : null;
};

/**
 * Whether a connector still executes against the security platform of a run (none for the internet): a connector
 * registered again against another platform no longer executes the runs created for the former one.
 */
export const isHuntConnectorBoundToRun = (connector: BasicStoreEntityConnector, run: Pick<BasicStoreEntityHuntRun, 'security_platform_id'>) => {
  return (connector.hunt_security_platform_id ?? null) === (run.security_platform_id ?? null);
};

/**
 * Security platforms a telemetry hunt runs on: the hunt scope filter over Security Platforms, or all of them.
 */
export const resolveHuntScopePlatforms = async (
  context: AuthContext,
  user: AuthUser,
  hunt: Pick<BasicStoreEntityHunt, 'hunt_scope'>,
): Promise<BasicStoreEntitySecurityPlatform[]> => {
  const filters = parseHuntFilterGroup(hunt.hunt_scope, 'hunt_scope');
  // Every matching platform, read page by page: a platform left out would never be hunted
  return fullEntitiesList<BasicStoreEntitySecurityPlatform>(context, user, [ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM], {
    filters: filters ?? undefined,
  });
};

/**
 * Hunt connectors that must execute the hunt.
 * - infrastructure hunts: every live connector of the internet platform
 * - telemetry hunts: every live connector bound to a security platform of the hunt scope
 *   (restricted to the requested platforms when given)
 * - indicator hunts: the same, among the connectors that look up indicator values
 * With includeOffline, the registered connectors that are temporarily offline are targeted as well: their runs wait
 * queued until the connector is back, or expire past the queue expiry.
 */
export const resolveHuntConnectorTargets = async (
  context: AuthContext,
  user: AuthUser,
  hunt: BasicStoreEntityHunt,
  requestedPlatformIds: string[] = [],
  options: { includeOffline?: boolean } = {},
): Promise<HuntConnectorTarget[]> => {
  const connectors = await listHuntConnectors(context, options.includeOffline !== true);
  if (hunt.hunt_type === HUNT_TYPE_INFRASTRUCTURE) {
    return connectors
      .filter((connector) => huntConnectorPlatform(connector) === HUNT_PLATFORM_INTERNET)
      .map((connector) => ({ connector, securityPlatform: null }));
  }
  const scopePlatforms = await resolveHuntScopePlatforms(context, user, hunt);
  const scopeById = new Map(scopePlatforms.map((platform) => [platform.internal_id, platform]));
  const requested = new Set(requestedPlatformIds);
  return connectors
    .filter((connector) => huntConnectorPlatform(connector) !== HUNT_PLATFORM_INTERNET)
    .filter((connector) => hunt.hunt_type !== HUNT_TYPE_INDICATORS || connector.hunt_supports_indicators === true)
    .filter((connector) => !!connector.hunt_security_platform_id && scopeById.has(connector.hunt_security_platform_id))
    .filter((connector) => requested.size === 0 || requested.has(connector.hunt_security_platform_id as string))
    .map((connector) => ({ connector, securityPlatform: scopeById.get(connector.hunt_security_platform_id as string) ?? null }));
};

const runsFilters = (connectorId: string, extra: { key: string; values: string[]; operator?: FilterOperator }[]) => ({
  mode: FilterMode.And,
  filters: [
    { key: ['connector_id'], values: [connectorId] },
    ...extra.map((filter) => ({ key: [filter.key], values: filter.values, operator: filter.operator ?? FilterOperator.Eq })),
  ],
  filterGroups: [],
});

const countRuns = async (context: AuthContext, filters: ReturnType<typeof runsFilters>) => {
  return elCount(context, SYSTEM_USER, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_HUNT_RUN], filters, noFiltersChecking: true });
};

export interface ConnectorBudget {
  canDispatch: boolean;
  reason?: string;
  // The sentence of the reason and its values, shown on the queued runs it holds back
  template?: string;
  values?: HuntMessageValues;
}

/**
 * Budget guard: maximum concurrent runs per connector and daily quota per connector.
 * Translation previews do not count against the daily quota (no execution on the platform).
 */
export const checkConnectorBudget = async (context: AuthContext, connector: BasicStoreEntityConnector, isPreview = false): Promise<ConnectorBudget> => {
  const maxConcurrent = Math.max(1, Math.min(
    HUNT_CONFIG.maxConcurrentRunsPerConnector,
    connector.hunt_max_concurrent_runs && connector.hunt_max_concurrent_runs > 0 ? connector.hunt_max_concurrent_runs : Number.MAX_SAFE_INTEGER,
  ));
  // A dispatched run occupies its connector until it terminates, even before the connector reports it running
  const activeRuns = await countRuns(context, runsFilters(connector.internal_id, [
    { key: 'hunt_run_status', values: HUNT_RUN_ACTIVE_STATUSES },
    { key: 'dispatched_at', values: [], operator: FilterOperator.NotNil },
  ]));
  if (activeRuns >= maxConcurrent) {
    const values = { connector: connector.name, count: activeRuns };
    return { canDispatch: false, reason: renderHuntMessage(HUNT_MESSAGES.queueConnectorBusy, values), template: HUNT_MESSAGES.queueConnectorBusy, values };
  }
  if (!isPreview) {
    const dayStart = new Date();
    dayStart.setUTCHours(0, 0, 0, 0);
    const runsToday = await countRuns(context, runsFilters(connector.internal_id, [
      { key: 'dispatched_at', values: [dayStart.toISOString()], operator: FilterOperator.Gte },
      { key: 'hunt_run_mode', values: [HUNT_RUN_MODE_PREVIEW], operator: FilterOperator.NotEq },
    ]));
    if (runsToday >= HUNT_CONFIG.dailyRunsPerConnector) {
      const values = { connector: connector.name, count: HUNT_CONFIG.dailyRunsPerConnector };
      return { canDispatch: false, reason: renderHuntMessage(HUNT_MESSAGES.queueConnectorQuota, values), template: HUNT_MESSAGES.queueConnectorQuota, values };
    }
  }
  return { canDispatch: true };
};

// The budget of a connector is read once per request, however many of its queued runs the request lists
const requestBudgets = new WeakMap<AuthContext, Map<string, Promise<ConnectorBudget>>>();

/**
 * Why a queued run waits, read when the run is: its connector deleted, offline or at one of its limits, its message sent
 * and not started yet, or the next dispatch of the hunt manager. Null for a run that does not wait.
 */
export const huntRunQueueReason = async (context: AuthContext, run: BasicStoreEntityHuntRun): Promise<HuntMessage | null> => {
  if (run.hunt_run_status !== HUNT_RUN_STATUS_QUEUED) {
    return null;
  }
  const connectors = await listHuntConnectors(context, false);
  const connector = connectors.find((candidate) => candidate.internal_id === run.connector_id);
  if (!connector) {
    return huntMessage(HUNT_MESSAGES.queueConnectorDeleted);
  }
  if (run.dispatched_at) {
    return huntMessage(HUNT_MESSAGES.queueSent, { connector: connector.name });
  }
  if (connector.active !== true) {
    return huntMessage(HUNT_MESSAGES.queueConnectorOffline, { connector: connector.name });
  }
  const isPreview = run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW;
  let budgets = requestBudgets.get(context);
  if (!budgets) {
    budgets = new Map();
    requestBudgets.set(context, budgets);
  }
  const key = `${connector.internal_id}:${isPreview}`;
  const budget = budgets.get(key) ?? checkConnectorBudget(context, connector, isPreview);
  budgets.set(key, budget);
  const { canDispatch, template, values } = await budget;
  return !canDispatch && template ? huntMessage(template, values) : huntMessage(HUNT_MESSAGES.queueNextDispatch);
};

const loadRefs = async (context: AuthContext, ids: string[] | undefined, type?: string) => {
  if (!ids || ids.length === 0) {
    return [];
  }
  return findByIds<BasicStoreEntity & Record<string, any>>(context, SYSTEM_USER, ids, type ? { type } : undefined);
};

const markingStandardIds = async (context: AuthContext, markingIds: string[] = []) => {
  if (markingIds.length === 0) {
    return [];
  }
  const markings = await findByIds<BasicStoreEntity>(context, SYSTEM_USER, markingIds);
  return markings.map((marking) => marking.standard_id);
};

/**
 * Builds the INTERNAL_HUNT queue message (contract section 4).
 */
export const buildHuntRunMessage = async (
  context: AuthContext,
  run: BasicStoreEntityHuntRun,
  hunt: BasicStoreEntityHunt,
  connector: BasicStoreEntityConnector,
  securityPlatform: BasicStoreEntity | null,
  workId: string,
  iocs: HuntIoc[] | null = null,
) => {
  const platform = huntConnectorPlatform(connector);
  const nativeQuery = normalizeNativeQueries(hunt.native_queries).find((query) => query.platform === platform) ?? null;
  const authorId = hunt[RELATION_CREATED_BY];
  // The evidence of a run is restricted like the run: the markings of the hunt and of its security platform, and the
  // organizations both are shared with. The attribution of an object to the run refuses a less restricted one
  const runMarkings = Array.from(new Set([...(hunt[RELATION_OBJECT_MARKING] ?? []), ...(run[RELATION_OBJECT_MARKING] ?? [])]));
  const [loadedTechniques, loadedTargets, sources, markings, organizations, loadedAuthor, markingDefinitions] = await Promise.all([
    loadRefs(context, hunt[RELATION_HUNT_TECHNIQUES], ENTITY_TYPE_ATTACK_PATTERN),
    loadRefs(context, hunt[RELATION_HUNT_TARGETS]),
    loadRefs(context, hunt[RELATION_HUNT_SOURCES]),
    markingStandardIds(context, runMarkings),
    loadRefs(context, run[RELATION_GRANTED_TO]),
    authorId ? loadRefs(context, [authorId]) : Promise.resolve([]),
    getEntitiesMapFromCache<BasicStoreEntityMarkingDefinition>(context, SYSTEM_USER, ENTITY_TYPE_MARKING_DEFINITION),
  ]);
  // The references are read with the system identity: one more restricted than the hunt, by its markings or its
  // organizations, is left out of the message. An indicator left out of the values an indicator hunt looks for is
  // therefore neither described nor sighted, and no restricted technique, target or author is named to the connector
  const isDisclosable = (element: BasicStoreEntity) => isDisclosableByHunt(hunt, element, markingDefinitions as Map<string, BasicStoreEntityMarkingDefinition>);
  const techniques = loadedTechniques.filter(isDisclosable);
  const targets = loadedTargets.filter(isDisclosable);
  const author = loadedAuthor.filter(isDisclosable);
  const indicators = sources.filter((source) => source.entity_type === ENTITY_TYPE_INDICATOR && isDisclosable(source));
  const isPreview = run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW;
  return {
    internal: {
      work_id: workId,
      applicant_id: null,
      mode: run.hunt_run_trigger === HUNT_RUN_TRIGGER_MANUAL || run.hunt_run_trigger === HUNT_RUN_TRIGGER_PREVIEW ? 'manual' : 'auto',
      trigger: run.hunt_run_trigger,
    },
    event: {
      event_type: CONNECTOR_INTERNAL_HUNT,
      mode: run.hunt_run_mode,
      hunt_run: { id: run.internal_id, attempt: run.attempt, trigger: run.hunt_run_trigger },
      hunt: {
        id: hunt.internal_id,
        standard_id: hunt.standard_id,
        name: hunt.name,
        hypothesis: hunt.hypothesis ?? '',
        hunt_type: hunt.hunt_type,
        sigma_rule: hunt.sigma_rule && hunt.sigma_rule.trim().length > 0 ? hunt.sigma_rule : null,
        native_query: nativeQuery,
        expected_observables: huntExpectedObservables(hunt),
        benign_patterns: hunt.benign_patterns ?? [],
        escalation_threshold: hunt.escalation_threshold,
        object_marking_refs: markings,
        granted_refs: organizations.map((organization) => organization.standard_id),
        created_by_ref: author.length > 0 ? author[0].standard_id : null,
        techniques: techniques.map((technique) => ({
          standard_id: technique.standard_id,
          name: technique.name,
          x_mitre_id: technique.x_mitre_id ?? null,
        })),
        targets: targets.map((target) => ({ standard_id: target.standard_id, entity_type: target.entity_type, name: target.name })),
        indicators: indicators
          .map((indicator) => ({ standard_id: indicator.standard_id, name: indicator.name, pattern_type: indicator.pattern_type, pattern: indicator.pattern })),
        // Indicator hunts: the values to look up, each with the indicators and observables it comes from
        iocs: (iocs ?? []).map((ioc) => ({
          key: ioc.key,
          observable_type: ioc.observable_type,
          hash_algorithm: ioc.hash_algorithm,
          value: ioc.value,
          sources: ioc.sources.map((source) => ({ standard_id: source.standard_id, entity_type: source.entity_type, name: source.name })),
        })),
      },
      time_window: { start: run.time_window_start, end: run.time_window_end },
      limits: {
        max_results: clampInteger(hunt.hunt_max_results, 1, HUNT_CONFIG.maxResultsPerRun, HUNT_DEFAULT_MAX_RESULTS),
        timeout_seconds: (isPreview ? HUNT_CONFIG.previewTimeoutMinutes : HUNT_CONFIG.runTimeoutMinutes) * 60,
        evidence_max_items: HUNT_CONFIG.evidenceMaxItems,
        evidence_max_value_length: HUNT_CONFIG.evidenceMaxValueLength,
        ioc_batch_size: HUNT_CONFIG.iocBatchSize,
      },
      security_platform: securityPlatform
        ? { id: securityPlatform.internal_id, standard_id: securityPlatform.standard_id, name: securityPlatform.name }
        : null,
    },
  };
};

const HUNT_CONNECTOR_DISPATCH_LOCK = 'hunt_connector_dispatch';

// Budget checks, slot reservations and publications of a connector are serialized with its binding to a security
// platform: concurrent starts and manager dispatches cannot all see the same free slot, a run is dispatched only once,
// and never published to a connector registered meanwhile against another platform
export const withConnectorDispatchLock = <T>(connectorId: string, action: () => Promise<T>): Promise<T> => {
  return withHuntLock(`${HUNT_CONNECTOR_DISPATCH_LOCK}_${connectorId}`, action);
};

/**
 * Publishes a reserved run to its connector queue, tracked by a work. On a failure the reservation is released and the
 * run stays queued for the next dispatch.
 */
const publishHuntRun = async (
  context: AuthContext,
  run: BasicStoreEntityHuntRun,
  hunt: BasicStoreEntityHunt,
  connector: BasicStoreEntityConnector,
  reserved: BasicStoreEntityHuntRun,
) => {
  // A run released because its publication was never recorded keeps the work of that publication: it is published
  // again under it, so the report of a message that did reach the connector is still bound to the run
  const heldWorkId = reserved.work_id ?? null;
  let workId: string | undefined = heldWorkId ?? undefined;
  try {
    const securityPlatform = run.security_platform_id
      ? (await findByIds<BasicStoreEntity>(context, SYSTEM_USER, [run.security_platform_id]))[0] ?? null
      : null;
    if (!workId) {
      const work = await createWork(context, HUNT_MANAGER_USER, connector, `Hunt ${hunt.name} (${run.hunt_run_trigger})`, hunt.standard_id, {
        fileMarkings: hunt[RELATION_OBJECT_MARKING] ?? [],
      });
      if (!work) {
        throw FunctionalError('The hunt run work cannot be created', { runId: run.internal_id });
      }
      workId = work.id;
    }
    // The values of an indicator hunt are read at the dispatch, so that a run follows the intelligence of the moment;
    // the run keeps them, the report of the connector is matched against them
    const iocs = hunt.hunt_type === HUNT_TYPE_INDICATORS ? (await resolveHuntIocSet(context, hunt)).iocs : null;
    const runPatch: Record<string, unknown> = { work_id: workId };
    if (iocs && run.hunt_run_mode !== HUNT_RUN_MODE_PREVIEW) {
      runPatch.ioc_results = iocs.map((ioc): HuntIocResult => ({
        key: ioc.key,
        observable_type: ioc.observable_type,
        hash_algorithm: ioc.hash_algorithm,
        value: ioc.value,
        source_ids: ioc.sources.map((source) => source.id),
        verdict: HUNT_IOC_VERDICT_PENDING,
        hits_count: 0,
        hosts: [],
      }));
    }
    // The run knows its work before the connector receives it: the first report of the connector is bound to it
    await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, runPatch);
    const message = await buildHuntRunMessage(context, run, hunt, connector, securityPlatform, workId, iocs);
    await pushToConnector(connector.internal_id, message);
  } catch (error) {
    if (heldWorkId) {
      // An earlier publication under this work may have reached the connector: the work and its link stay, only the
      // slot is released, and the run stays queued for the next dispatch
      await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: null });
    } else {
      // Nothing was published: the work no connector will ever process is deleted (every retry creates its own), the
      // slot and the work link are released and the run stays queued for the next dispatch
      if (workId) {
        await deleteWork(context, HUNT_MANAGER_USER, workId)
          .catch((deleteError: unknown) => logApp.error('[OPENCTI-MODULE] Hunt run work cannot be deleted after a failed dispatch', { cause: deleteError, runId: run.internal_id, workId }));
      }
      await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: null, work_id: null });
    }
    throw error;
  }
  return workId;
};

/**
 * Pushes a queued run to its connector queue, tracked by a work. Returns false when the budget defers the run.
 * The run occupies its budget slot from the reservation of its dispatch date, before its message is published.
 */
export const dispatchHuntRun = async (
  context: AuthContext,
  run: BasicStoreEntityHuntRun,
  hunt: BasicStoreEntityHunt,
): Promise<boolean> => {
  const connectors = await listHuntConnectors(context, false);
  const connector = connectors.find((c) => c.internal_id === run.connector_id);
  if (!connector || connector.active !== true) {
    logApp.debug('[OPENCTI-MODULE] Hunt run kept queued, connector is not alive', { runId: run.internal_id, connectorId: run.connector_id });
    return false;
  }
  // Never sent to another platform than its own: the hunt manager cancels the run (cancelOrphanRunsOfPage)
  if (!isHuntConnectorBoundToRun(connector, run)) {
    logApp.debug('[OPENCTI-MODULE] Hunt run kept queued, its connector executes against another security platform', { runId: run.internal_id, connectorId: run.connector_id });
    return false;
  }
  // Reserved and published under the dispatch lock, which a registration of the connector takes to bind it: the
  // registration read under the lock (its liveness, binding, limits and query contract) still holds when the message is
  // published
  const workId = await withConnectorDispatchLock(connector.internal_id, async () => {
    const [current] = await findByIds<BasicStoreEntityHuntRun>(context, SYSTEM_USER, [run.internal_id], { type: ENTITY_TYPE_HUNT_RUN });
    if (!current || current.hunt_run_status !== HUNT_RUN_STATUS_QUEUED || current.dispatched_at) {
      logApp.debug('[OPENCTI-MODULE] Hunt run already dispatched or settled', { runId: run.internal_id });
      return null;
    }
    const bound = (await listHuntConnectors(context, false)).find((candidate) => candidate.internal_id === connector.internal_id);
    if (!bound || bound.active !== true) {
      logApp.debug('[OPENCTI-MODULE] Hunt run kept queued, connector is not alive', { runId: run.internal_id, connectorId: run.connector_id });
      return null;
    }
    if (!isHuntConnectorBoundToRun(bound, current)) {
      logApp.debug('[OPENCTI-MODULE] Hunt run kept queued, its connector was registered against another security platform', { runId: run.internal_id, connectorId: run.connector_id });
      return null;
    }
    const budget = await checkConnectorBudget(context, bound, run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW);
    if (!budget.canDispatch) {
      logApp.debug('[OPENCTI-MODULE] Hunt run deferred by budget', { runId: run.internal_id, reason: budget.reason });
      return null;
    }
    await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: now() });
    return publishHuntRun(context, run, hunt, bound, current);
  });
  if (!workId) {
    return false;
  }
  // Published: the hunt manager never releases this reservation (requeueUnpublishedHuntRuns). Outside the publication, a
  // failure to record the date never undoes it: the run is published again under the same work after the grace
  await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { published_at: now() })
    .catch((error: unknown) => logApp.warn('[OPENCTI-MODULE] Hunt run publication date cannot be recorded, the run is published again under its work after the grace', { cause: error, runId: run.internal_id, workId }));
  return true;
};
