import { findByIds } from './hunt-loaders';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { logApp } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { withHuntLock } from './hunt-lock';
import { getEntitiesListFromCache } from '../../database/cache';
import { completeConnector } from '../../database/repository';
import { pushToConnector } from '../../database/rabbitmq';
import { elCount } from '../../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { fullEntitiesList } from '../../database/middleware-loader';
import { patchAttribute } from '../../database/middleware';
import { createWork } from '../../domain/work';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { CONNECTOR_INTERNAL_HUNT } from '../../schema/general';
import { RELATION_CREATED_BY, RELATION_OBJECT_MARKING } from '../../schema/stixRefRelationship';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import { HUNT_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import { now } from '../../utils/format';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../securityPlatform/securityPlatform-types';
import { ENTITY_TYPE_ATTACK_PATTERN } from '../../schema/stixDomainObject';
import { ENTITY_TYPE_INDICATOR } from '../indicator/indicator-types';
import { type BasicStoreEntityHunt, HUNT_PLATFORM_INTERNET, HUNT_TYPE_INFRASTRUCTURE, RELATION_HUNT_SOURCES, RELATION_HUNT_TARGETS, RELATION_HUNT_TECHNIQUES } from './hunt-types';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_QUEUED,
  HUNT_RUN_TRIGGER_MANUAL,
  HUNT_RUN_TRIGGER_PREVIEW,
} from './huntRun/huntRun-types';
import { clampInteger, HUNT_CONFIG, HUNT_DEFAULT_MAX_RESULTS, normalizeNativeQueries, parseHuntFilterGroup } from './hunt-utils';

export interface HuntConnectorTarget {
  connector: BasicStoreEntityConnector;
  securityPlatform: BasicStoreEntitySecurityPlatform | null;
}

/**
 * Active hunt connectors, completed with their liveness (a connector pings every minute).
 */
export const listHuntConnectors = async (context: AuthContext, onlyAlive = true): Promise<BasicStoreEntityConnector[]> => {
  const connectors = await getEntitiesListFromCache<BasicStoreEntityConnector>(context, SYSTEM_USER, ENTITY_TYPE_CONNECTOR);
  return connectors
    .filter((connector) => connector.connector_type === CONNECTOR_INTERNAL_HUNT)
    .map((connector) => completeConnector(connector) as BasicStoreEntityConnector)
    .filter((connector) => !onlyAlive || connector.active === true);
};

const huntConnectorPlatform = (connector: BasicStoreEntityConnector): string | null => {
  if (connector.hunt_platform) {
    return connector.hunt_platform;
  }
  const scope = completeConnector(connector)?.connector_scope ?? [];
  return scope.length > 0 ? String(scope[0]).toLowerCase() : null;
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
 */
export const resolveHuntConnectorTargets = async (
  context: AuthContext,
  user: AuthUser,
  hunt: BasicStoreEntityHunt,
  requestedPlatformIds: string[] = [],
): Promise<HuntConnectorTarget[]> => {
  const connectors = await listHuntConnectors(context, true);
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
    return { canDispatch: false, reason: `connector ${connector.name} already runs ${activeRuns} hunts` };
  }
  if (!isPreview) {
    const dayStart = new Date();
    dayStart.setUTCHours(0, 0, 0, 0);
    const runsToday = await countRuns(context, runsFilters(connector.internal_id, [
      { key: 'dispatched_at', values: [dayStart.toISOString()], operator: FilterOperator.Gte },
      { key: 'hunt_run_mode', values: [HUNT_RUN_MODE_PREVIEW], operator: FilterOperator.NotEq },
    ]));
    if (runsToday >= HUNT_CONFIG.dailyRunsPerConnector) {
      return { canDispatch: false, reason: `connector ${connector.name} reached its daily quota of ${HUNT_CONFIG.dailyRunsPerConnector} runs` };
    }
  }
  return { canDispatch: true };
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
) => {
  const platform = huntConnectorPlatform(connector);
  const nativeQuery = normalizeNativeQueries(hunt.native_queries).find((query) => query.platform === platform) ?? null;
  const authorId = hunt[RELATION_CREATED_BY];
  const [techniques, targets, sources, markings, author] = await Promise.all([
    loadRefs(context, hunt[RELATION_HUNT_TECHNIQUES], ENTITY_TYPE_ATTACK_PATTERN),
    loadRefs(context, hunt[RELATION_HUNT_TARGETS]),
    loadRefs(context, hunt[RELATION_HUNT_SOURCES]),
    markingStandardIds(context, hunt[RELATION_OBJECT_MARKING]),
    authorId ? loadRefs(context, [authorId]) : Promise.resolve([]),
  ]);
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
        expected_observables: hunt.expected_observables ?? [],
        benign_patterns: hunt.benign_patterns ?? [],
        escalation_threshold: hunt.escalation_threshold,
        object_marking_refs: markings,
        created_by_ref: author.length > 0 ? author[0].standard_id : null,
        techniques: techniques.map((technique) => ({
          standard_id: technique.standard_id,
          name: technique.name,
          x_mitre_id: technique.x_mitre_id ?? null,
        })),
        targets: targets.map((target) => ({ standard_id: target.standard_id, entity_type: target.entity_type, name: target.name })),
        indicators: sources
          .filter((source) => source.entity_type === ENTITY_TYPE_INDICATOR)
          .map((indicator) => ({ standard_id: indicator.standard_id, name: indicator.name, pattern_type: indicator.pattern_type, pattern: indicator.pattern })),
      },
      time_window: { start: run.time_window_start, end: run.time_window_end },
      limits: {
        max_results: clampInteger(hunt.hunt_max_results, 1, HUNT_CONFIG.maxResultsPerRun, HUNT_DEFAULT_MAX_RESULTS),
        timeout_seconds: (isPreview ? HUNT_CONFIG.previewTimeoutMinutes : HUNT_CONFIG.runTimeoutMinutes) * 60,
        evidence_max_items: HUNT_CONFIG.evidenceMaxItems,
        evidence_max_value_length: HUNT_CONFIG.evidenceMaxValueLength,
      },
      security_platform: securityPlatform
        ? { id: securityPlatform.internal_id, standard_id: securityPlatform.standard_id, name: securityPlatform.name }
        : null,
    },
  };
};

const HUNT_CONNECTOR_DISPATCH_LOCK = 'hunt_connector_dispatch';

// Budget checks and slot reservations of a connector are serialized: concurrent starts and manager dispatches cannot
// all see the same free slot, and a run is dispatched only once
const withConnectorDispatchLock = <T>(connectorId: string, reservation: () => Promise<T>): Promise<T> => {
  return withHuntLock(`${HUNT_CONNECTOR_DISPATCH_LOCK}_${connectorId}`, reservation);
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
  const reserved = await withConnectorDispatchLock(connector.internal_id, async () => {
    const [current] = await findByIds<BasicStoreEntityHuntRun>(context, SYSTEM_USER, [run.internal_id], { type: ENTITY_TYPE_HUNT_RUN });
    if (!current || current.hunt_run_status !== HUNT_RUN_STATUS_QUEUED || current.dispatched_at) {
      logApp.debug('[OPENCTI-MODULE] Hunt run already dispatched or settled', { runId: run.internal_id });
      return false;
    }
    const budget = await checkConnectorBudget(context, connector, run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW);
    if (!budget.canDispatch) {
      logApp.debug('[OPENCTI-MODULE] Hunt run deferred by budget', { runId: run.internal_id, reason: budget.reason });
      return false;
    }
    await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: now() });
    return true;
  });
  if (!reserved) {
    return false;
  }
  let workId: string;
  try {
    const securityPlatform = run.security_platform_id
      ? (await findByIds<BasicStoreEntity>(context, SYSTEM_USER, [run.security_platform_id]))[0] ?? null
      : null;
    const work = await createWork(context, HUNT_MANAGER_USER, connector, `Hunt ${hunt.name} (${run.hunt_run_trigger})`, hunt.standard_id, {
      fileMarkings: hunt[RELATION_OBJECT_MARKING] ?? [],
    });
    if (!work) {
      throw FunctionalError('The hunt run work cannot be created', { runId: run.internal_id });
    }
    workId = work.id;
    const message = await buildHuntRunMessage(context, run, hunt, connector, securityPlatform, workId);
    await pushToConnector(connector.internal_id, message);
  } catch (error) {
    // Nothing was published: the slot is released and the run stays queued for the next dispatch
    await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: null });
    throw error;
  }
  await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { work_id: workId });
  return true;
};
