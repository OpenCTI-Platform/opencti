import { LRUCache } from 'lru-cache';
import { v4 as uuidv4 } from 'uuid';
import { findByIds } from '../hunt-loaders';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity, BasicStoreObject } from '../../../types/store';
import type { BasicStoreEntityConnector } from '../../../types/connector';
import { BUS_TOPICS, logApp } from '../../../config/conf';
import { ForbiddenAccess, FunctionalError, ResourceNotFoundError } from '../../../config/errors';
import { withHuntLock } from '../hunt-lock';
import { checkHuntEditAccess } from '../hunt-access';
import { createEntity, patchAttribute } from '../../../database/middleware';
import {
  type EntityOptions,
  fullEntitiesList,
  internalFindByIds,
  internalLoadById,
  pageEntitiesConnection,
  storeLoadById,
  topEntitiesList,
} from '../../../database/middleware-loader';
import { elAggregationCount, elHistogramCount, elHistogramSum, elRawUpdateByQuery } from '../../../database/engine';
import { fillTimeSeries, READ_INDEX_INTERNAL_OBJECTS } from '../../../database/utils';
import { notify } from '../../../database/redis';
import { pushToConnector } from '../../../database/rabbitmq';
import { createWork, deleteWork } from '../../../domain/work';
import { publishUserAction } from '../../../listener/UserActionListener';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_HUNT } from '../../../schema/general';
import { ENTITY_TYPE_CONNECTOR } from '../../../schema/internalObject';
import { isStixCyberObservable } from '../../../schema/stixCyberObservable';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../schema/stixDomainObject';
import { isStixSightingRelationship } from '../../../schema/stixSightingRelationship';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import {
  FilterMode,
  FilterOperator,
  OrderingMode,
  type FilterGroup,
  type HuntConnectorCheckReportInput,
  type HuntConnectorRegisterInput,
  type HuntRunEvidenceAddInput,
  type HuntRunReportInput,
  type HuntRunVerdictInput,
} from '../../../generated/graphql';
import { HUNT_MANAGER_USER, isBypassUser, SYSTEM_USER } from '../../../utils/access';
import { addFilter } from '../../../utils/filtering/filtering-utils';
import { now } from '../../../utils/format';
import { checkEnterpriseEdition, isEnterpriseEdition } from '../../../enterprise-edition/ee';
import { addHuntRunCount, addHuntTriageCount, addHuntVerdictCount } from '../../../manager/telemetryManager';
import { addSecurityPlatform } from '../../securityPlatform/securityPlatform-domain';
import { ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM, type BasicStoreEntitySecurityPlatform } from '../../securityPlatform/securityPlatform-types';
import { resolveAgentJwtUser } from '../../playbook/components/ai-agent-shared';
import {
  type BasicStoreEntityHunt,
  ENTITY_TYPE_HUNT,
  HUNT_PLATFORM_INTERNET,
  HUNT_PLATFORMS,
  HUNT_STATUS_DRAFT,
  HUNT_STATUS_RETIRED,
  HUNT_TYPE_INDICATORS,
  RELATION_HUNT_TARGETS,
  RELATION_HUNT_TECHNIQUES,
} from '../hunt-types';
import { dispatchHuntRun, huntConnectorPlatform, listHuntConnectors, resolveHuntConnectorTargets, withConnectorDispatchLock } from '../hunt-dispatch';
import {
  clampInteger,
  HUNT_CONFIG,
  HUNT_DEFAULT_TIME_WINDOW_HOURS,
  huntRunRestrictions,
  huntHitDates,
  identifyingHitKeys,
  markMatchedEvidence,
  mergeEvidence,
  mergeHits,
  sanitizeEvidence,
  sanitizeHitKeys,
  sanitizeHits,
  splitHitsByKeys,
  techniqueValidationStatus,
  truncate,
} from '../hunt-utils';
import { huntLogicError } from '../hunt-validators';
import { HUNT_MESSAGES, renderHuntMessage } from '../hunt-messages';
import {
  findHuntTranslation,
  findUnresolvedHuntTechniques,
  huntLogicFingerprint,
  huntTranslationMessage,
  isDeterministicHuntFailure,
  isTerminalHuntRunFailure,
} from '../hunt-logic';
import { isReadableByReadersOf, resolveHuntIocSet } from '../hunt-iocs';
import { countIocHits, hasUnsearchedIoc, linkIocDeployments, mergeHuntIocResults } from './huntRun-iocs';
import { type HuntRunInformationPatch, updateHuntRunInformation } from '../hunt-stats';
import { writeHuntCoverageResult } from '../hunt-coverage';
import {
  continueHuntIncident,
  createHuntIncidentInWorkspace,
  createHuntIncidentWorkspace,
  findOpenHuntIncident,
  type OpenHuntIncident,
  parseIncidentProposal,
} from '../hunt-incident';
import { createHuntHitObservations } from '../hunt-hit-observations';
import { upsertHuntSightings } from '../hunt-sightings';
import { isHuntRunRemembered, recordHuntHits } from '../huntHitRecord/huntHitRecord-domain';
import { callHuntAgent, HUNT_TRIAGE_INTENT, validateHuntTriageResult } from '../hunt-agents';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_CONNECTION_CHECK_FAILED,
  HUNT_CONNECTION_CHECK_MODE,
  HUNT_CONNECTION_CHECK_PASSED,
  HUNT_CONNECTION_CHECK_PENDING,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_AUTONOMOUS_TRIGGERS,
  HUNT_RUN_FINALIZABLE_STATUSES,
  HUNT_RUN_INCREMENTAL_TRIGGERS,
  HUNT_RUN_MODE_EXECUTE,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_CANCELLED,
  HUNT_RUN_STATUS_COMPLETED,
  HUNT_RUN_STATUS_FAILED,
  HUNT_RUN_STATUS_QUEUED,
  HUNT_RUN_STATUS_RUNNING,
  HUNT_RUN_STATUS_TIMEOUT,
  HUNT_RUN_TERMINAL_STATUSES,
  HUNT_RUN_TRIGGER_EMULATION,
  HUNT_RUN_TRIGGER_PREVIEW,
  HUNT_RUN_TRIGGER_RETRY,
  HUNT_VERDICT_BENIGN,
  HUNT_VERDICT_INCONCLUSIVE,
  HUNT_VERDICT_PENDING,
  HUNT_VERDICT_SOURCE_AGENT,
  HUNT_VERDICT_SOURCE_ANALYST,
  HUNT_VERDICT_SOURCE_AUTO,
  HUNT_VERDICT_SOURCES,
  HUNT_VERDICT_TRUE_POSITIVE,
  type HuntPlaybookContext,
} from './huntRun-types';

const ERROR_MESSAGE_MAX_LENGTH = 4000;
const TRANSLATED_QUERY_MAX_LENGTH = 65536;
// The result objects a run keeps for its Results drawer and its playbooks, at least as many as the results a hunt may
// request: a run that sent more has partial results
export const HUNT_RUN_RESULT_IDS_MAX = Math.max(5000, HUNT_CONFIG.maxResultsPerRun);
// The objects of a report are sent after it (contract section 5): their STIX ids are kept, and every reader loads
// them with its own identity, the playbook with the one of the hunt connector of the run
const STIX_ID_PATTERN = /^[a-z][a-z0-9-]*--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const TRIAGE_HISTORY_SIZE = 10;
const MAX_LANGUAGES = 20;

// region read
export const findHuntRunById = (context: AuthContext, user: AuthUser, id: string) => {
  return storeLoadById<BasicStoreEntityHuntRun>(context, user, id, ENTITY_TYPE_HUNT_RUN);
};

export const findHuntRunsPaginated = (context: AuthContext, user: AuthUser, args: EntityOptions<BasicStoreEntityHuntRun>) => {
  return pageEntitiesConnection<BasicStoreEntityHuntRun>(context, user, [ENTITY_TYPE_HUNT_RUN], args);
};

export const findHuntRunsForHunt = (context: AuthContext, user: AuthUser, huntId: string, args: EntityOptions<BasicStoreEntityHuntRun>) => {
  const filters = addFilter(args.filters as FilterGroup | undefined, 'hunt_id', huntId);
  return findHuntRunsPaginated(context, user, { orderBy: 'created_at', orderMode: OrderingMode.Desc, ...args, filters });
};

/** What the results of a run hold, by kind. */
export interface HuntRunResultsSummary {
  sightings: number;
  observed_data: number;
  observables: number;
  others: number;
}

/** Counts the results of a run by kind, each object once. */
export const summarizeHuntRunResults = (results: ReadonlyArray<{ internal_id: string; entity_type: string }>): HuntRunResultsSummary => {
  const summary: HuntRunResultsSummary = { sightings: 0, observed_data: 0, observables: 0, others: 0 };
  const types = new Map(results.map((result) => [result.internal_id, result.entity_type]));
  types.forEach((entityType) => {
    if (isStixSightingRelationship(entityType)) {
      summary.sightings += 1;
    } else if (entityType === ENTITY_TYPE_CONTAINER_OBSERVED_DATA) {
      summary.observed_data += 1;
    } else if (isStixCyberObservable(entityType)) {
      summary.observables += 1;
    } else {
      summary.others += 1;
    }
  });
  return summary;
};

interface ReadableHuntRunResults {
  internalIds: string[];
  visibleIds: string[];
  summary: HuntRunResultsSummary;
}

// The results of a run the user can read, as internal ids in the order the run recorded them (markings and
// organizations of every object apply), with their summary by kind. Access is resolved over every recorded id before any
// pagination, reading their identifiers and types only, so counts never include the objects the user cannot read and no
// object is loaded in full. Paging through thousands of results resolves the readable ids once per reader and version of
// the run, not on every page. Every page still loads its objects with the access of the reader, so the short ttl only
// bounds how long a count can lag behind an access change; the size bound counts ids, a run holding thousands of them
const readableResultIdsCache = new LRUCache<string, ReadableHuntRunResults>({
  maxSize: 200_000,
  sizeCalculation: (value) => value.internalIds.length + value.visibleIds.length + 1,
  ttl: 30 * 1000,
});

const readableHuntRunResultIds = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun): Promise<ReadableHuntRunResults> => {
  const ids = run.result_ids ?? [];
  if (ids.length === 0) {
    return { internalIds: [], visibleIds: [], summary: summarizeHuntRunResults([]) };
  }
  const cacheKey = [user.id, context.draft_context ?? '', run.internal_id, String(run.updated_at), ids.length].join('|');
  const cached = readableResultIdsCache.get(cacheKey);
  if (cached) {
    return cached;
  }
  const readable = await internalFindByIds<BasicStoreObject>(context, user, ids, { baseData: true, baseFields: ['x_opencti_stix_ids'] }) as BasicStoreObject[];
  const internalIdOf = new Map<string, string>();
  readable.forEach((element) => {
    [element.internal_id, element.standard_id, ...(element.x_opencti_stix_ids ?? [])].forEach((id) => internalIdOf.set(id, element.internal_id));
  });
  const internalIds = Array.from(new Set(ids.map((id) => internalIdOf.get(id)).filter((id): id is string => !!id)));
  const resolved = { internalIds, visibleIds: ids.filter((id) => internalIdOf.has(id)), summary: summarizeHuntRunResults(readable) };
  readableResultIdsCache.set(cacheKey, resolved);
  return resolved;
};

/**
 * Objects produced by a run, as visible to the user, paginated after the cursor of the previous page: only the objects
 * of the page are loaded.
 */
export const findHuntRunResults = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun, first = 50, after?: string | null) => {
  const { internalIds } = await readableHuntRunResultIds(context, user, run);
  const position = after ? internalIds.indexOf(after) : -1;
  // An unknown cursor is refused rather than read as the first page again, which would make a client paginate forever
  if (after && position < 0) {
    throw FunctionalError('The cursor is not a result of this run you can read', { runId: run.internal_id, after });
  }
  const start = position + 1;
  const pageIds = internalIds.slice(start, start + Math.min(Math.max(first, 1), 500));
  const loaded = await findByIds<BasicStoreObject>(context, user, pageIds);
  const loadedById = new Map(loaded.map((element) => [element.internal_id, element]));
  const page = pageIds.map((id) => loadedById.get(id)).filter((element): element is BasicStoreObject => !!element);
  // The cursors are positions in the readable ids: an object deleted or hidden since they were resolved is skipped, the
  // next page still continues after it instead of restarting from the first page
  return {
    edges: page.map((element) => ({ cursor: element.internal_id, node: element })),
    pageInfo: {
      startCursor: pageIds[0] ?? '',
      endCursor: pageIds[pageIds.length - 1] ?? '',
      hasNextPage: start + pageIds.length < internalIds.length,
      hasPreviousPage: start > 0,
      globalCount: internalIds.length,
    },
  };
};

// The result ids of a run are only disclosed for the result objects the caller can read, like its results
export const findHuntRunResultIds = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const { visibleIds } = await readableHuntRunResultIds(context, user, run);
  return visibleIds;
};

// What a run produced, by kind, over the same results the caller can read in its results
export const findHuntRunResultsSummary = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const { summary } = await readableHuntRunResultIds(context, user, run);
  return summary;
};

const loadHuntForRun = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const hunt = await storeLoadById<BasicStoreEntityHunt>(context, user, run.hunt_id, ENTITY_TYPE_HUNT);
  if (!hunt) {
    throw ResourceNotFoundError('Hunt of the run cannot be found', { runId: run.internal_id });
  }
  return hunt;
};

const loadHuntForRunEdit = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const hunt = await loadHuntForRun(context, user, run);
  await checkHuntEditAccess(context, user, hunt);
  return hunt;
};

// Whether a hunt exists is read once per request, however many of its runs the request lists
const requestHuntExistence = new WeakMap<AuthContext, Map<string, Promise<boolean>>>();

/**
 * Whether the hunt of a run was deleted (in the trash or for good), read with the hunt manager identity: a hunt the user
 * cannot read is not a deleted one.
 */
export const isHuntRunHuntDeleted = async (context: AuthContext, run: Pick<BasicStoreEntityHuntRun, 'hunt_id'>) => {
  let existence = requestHuntExistence.get(context);
  if (!existence) {
    existence = new Map();
    requestHuntExistence.set(context, existence);
  }
  const exists = existence.get(run.hunt_id)
    ?? internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT }).then((hunt) => !!hunt);
  existence.set(run.hunt_id, exists);
  return !(await exists);
};
// endregion

// region creation and dispatch
export interface HuntRunRequest {
  trigger: string;
  mode?: string;
  securityPlatformIds?: string[];
  connectorIds?: string[];
  timeWindowHours?: number | null;
  windowStart?: string | null;
  windowEnd?: string | null;
  aevInjectId?: string | null;
  securityCoverageId?: string | null;
  techniqueId?: string | null;
  triggeredBy?: string | null;
  // The user starting a manual run, a preview or a manual retry: only the security platforms this user can read are targeted
  requester?: AuthUser | null;
  dispatch?: boolean;
  // Runs beyond this number stay queued and are dispatched by the hunt manager at a later tick (its per-tick budget)
  dispatchLimit?: number;
  // Autonomous executions: the runs of the connectors temporarily offline are created and wait queued for them
  includeOfflineConnectors?: boolean;
  attempt?: number;
  // The run a retry replaces
  retryOf?: string | null;
  // A retry searches the window of the run it replaces, which continued this run
  continuesRunId?: string | null;
  // A retry escalates as the run it replaces; any other run as its trigger and its hunt decide
  autoEscalation?: boolean | null;
  playbook?: {
    playbookId: string;
    executionId: string;
    stepId: string;
    // The entity whose event started the execution
    instanceId?: string | null;
    // Continuation of the playbook, handed to the first run once every run of the hunt is created
    context?: HuntPlaybookContext;
  } | null;
}

/**
 * The time window of a recurring run: from where the previous completed run of the same logic of the hunt on the same
 * security platform ended, minus the lookback overlap that catches the events indexed late, never longer than the time
 * window of the hunt. Without such a run (none yet, or the logic changed since), or one older than the time window, the
 * full time window (continued is false).
 */
export const computeHuntRunWindow = (end: Date, hours: number, lookbackMinutes: number, previousEnd?: string | Date | null) => {
  const full = new Date(end.getTime() - hours * 3600 * 1000);
  const previous = previousEnd ? new Date(previousEnd) : null;
  if (!previous || Number.isNaN(previous.getTime())) {
    return { start: full, continued: false };
  }
  const since = new Date(previous.getTime() - lookbackMinutes * 60 * 1000);
  if (since.getTime() <= full.getTime()) {
    return { start: full, continued: false };
  }
  // A previous window ending after now (clock drift between nodes) still leaves the overlap to search
  const start = since.getTime() < end.getTime() ? since : new Date(end.getTime() - Math.max(lookbackMinutes, 1) * 60 * 1000);
  return { start, continued: true };
};

/**
 * The completed run of a hunt on a security platform (null: on the internet) whose time window ends last, among the runs
 * of the current logic of the hunt: a run of an earlier rule or query never searched for what the current one matches.
 */
export const findLastCompletedHuntRun = async (context: AuthContext, huntId: string, securityPlatformId: string | null, logicFingerprint: string) => {
  const [previous] = await topEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    first: 1,
    orderBy: 'time_window_end',
    orderMode: OrderingMode.Desc,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_id'], values: [huntId] },
        securityPlatformId
          ? { key: ['security_platform_id'], values: [securityPlatformId] }
          : { key: ['security_platform_id'], values: [], operator: FilterOperator.Nil },
        { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_COMPLETED] },
        { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
        { key: ['hunt_logic_fingerprint'], values: [logicFingerprint] },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  return previous ?? null;
};

/** Hits of a run never seen before for its hunt on its platform: every hit when the connector identifies none. */
export const huntRunNewHits = (run: Pick<BasicStoreEntityHuntRun, 'hits_new_count' | 'hits_count'>) => run.hits_new_count ?? run.hits_count ?? 0;

// The tagged techniques a run reports as not found: a lookup that fails reports none rather than blocking the run
const findRunUnresolvedTechniques = async (context: AuthContext, hunt: BasicStoreEntityHunt) => {
  try {
    const unresolved = await findUnresolvedHuntTechniques(context, HUNT_MANAGER_USER, hunt.sigma_rule);
    if (unresolved.length > 0) {
      logApp.info('[OPENCTI-MODULE] Hunt run tagged techniques not found in the knowledge base', { huntId: hunt.internal_id, count: unresolved.length });
    }
    return unresolved;
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Hunt run tagged techniques lookup failed', { cause: error, huntId: hunt.internal_id });
    return [];
  }
};

type HuntRunAccess = { [RELATION_OBJECT_MARKING]?: string[]; [RELATION_GRANTED_TO]?: string[] };

/**
 * The run summary of a hunt (last run, its status and hits) is read, sorted and filtered with the access of the hunt: it
 * only follows the runs every reader of the hunt can read, never a run its security platform restricts further, which
 * only the readers of that run see among the runs of the hunt. Written when one of the runs is readable so, never over
 * the summary of a later run.
 */
export const recordHuntRunSummary = async (context: AuthContext, hunt: BasicStoreEntityHunt, runs: HuntRunAccess[], patch: HuntRunInformationPatch) => {
  const huntMarkings = hunt[RELATION_OBJECT_MARKING] ?? [];
  const huntOrganizations = hunt[RELATION_GRANTED_TO] ?? [];
  // Restricted as its hunt only: no marking the hunt does not carry, shared with every organization of the hunt
  const asOpenAsHunt = (run: HuntRunAccess) => (run[RELATION_OBJECT_MARKING] ?? []).every((id) => huntMarkings.includes(id))
    && huntOrganizations.every((id) => (run[RELATION_GRANTED_TO] ?? []).includes(id));
  for (let index = 0; index < runs.length; index += 1) {
    if (asOpenAsHunt(runs[index]) || await isReadableByReadersOf(context, hunt, runs[index])) {
      await updateHuntRunInformation(context, hunt.internal_id, patch, { onlyIfNewer: true });
      return true;
    }
  }
  return false;
};

interface HuntRunCreation {
  runs: BasicStoreEntityHuntRun[];
  // The security platforms (or connectors, on the internet) left without a run when the creation was interrupted
  notCreatedOn: string[];
}

const createHuntRunsOnTargets = async (context: AuthContext, hunt: BasicStoreEntityHunt, request: HuntRunRequest): Promise<HuntRunCreation> => {
  const mode = request.mode ?? HUNT_RUN_MODE_EXECUTE;
  if (context.draft_context) {
    throw FunctionalError('A hunt runs once it is validated from its draft', { huntId: hunt.internal_id });
  }
  // Draft and retired hunts never execute, their logic can still be previewed
  if (mode === HUNT_RUN_MODE_EXECUTE && [HUNT_STATUS_DRAFT, HUNT_STATUS_RETIRED].includes(hunt.hunt_status)) {
    throw FunctionalError(`A hunt in ${hunt.hunt_status} status does not run`, { huntId: hunt.internal_id, status: hunt.hunt_status });
  }
  // Paused hunts can be saved without logic and still be run manually
  const logicError = mode === HUNT_RUN_MODE_EXECUTE ? huntLogicError(hunt) : null;
  if (logicError) {
    throw FunctionalError(`The hunt cannot run: ${logicError.message}`, { huntId: hunt.internal_id, field: logicError.field });
  }
  // An indicator hunt whose indicators all lost their values (removed, revoked, restricted) has nothing to look up
  if (hunt.hunt_type === HUNT_TYPE_INDICATORS && (await resolveHuntIocSet(context, hunt)).iocs.length === 0) {
    throw FunctionalError(`The hunt cannot run: ${HUNT_MESSAGES.logicIndicatorsEmpty}`, { huntId: hunt.internal_id, field: 'hunt_ioc_values' });
  }
  const resolved = await resolveHuntConnectorTargets(context, request.requester ?? HUNT_MANAGER_USER, hunt, request.securityPlatformIds ?? [], {
    includeOffline: request.includeOfflineConnectors === true && mode === HUNT_RUN_MODE_EXECUTE,
  });
  let targets = resolved.flatMap((target) => {
    const restrictions = huntRunRestrictions(hunt, target.securityPlatform);
    if (!restrictions) {
      logApp.warn('[OPENCTI-MODULE] Hunt run skipped, the hunt and its security platform are shared with different organizations', {
        huntId: hunt.internal_id,
        securityPlatformId: target.securityPlatform?.internal_id,
      });
      return [];
    }
    return [{ ...target, restrictions }];
  });
  if (request.connectorIds && request.connectorIds.length > 0) {
    targets = targets.filter((target) => request.connectorIds?.includes(target.connector.internal_id));
  }
  if (mode === HUNT_RUN_MODE_PREVIEW) {
    targets = targets.filter((target) => target.connector.hunt_supports_preview !== false).slice(0, 1);
  }
  const windowEnd = request.windowEnd ? new Date(request.windowEnd) : new Date();
  const hours = clampInteger(request.timeWindowHours ?? hunt.time_window_hours, 1, HUNT_CONFIG.maxTimeWindowHours, HUNT_DEFAULT_TIME_WINDOW_HOURS);
  const fullWindowStart = request.windowStart ? new Date(request.windowStart) : new Date(windowEnd.getTime() - hours * 3600 * 1000);
  if (fullWindowStart.getTime() >= windowEnd.getTime()) {
    throw FunctionalError('The hunt time window start must be before its end', { windowStart: fullWindowStart, windowEnd });
  }
  // Recurring runs search since the previous run of the hunt on their platform; any explicit window is kept as it is
  const incremental = mode === HUNT_RUN_MODE_EXECUTE && HUNT_RUN_INCREMENTAL_TRIGGERS.includes(request.trigger) && !request.windowStart && !request.windowEnd;
  const runs: BasicStoreEntityHuntRun[] = [];
  const logicFingerprint = huntLogicFingerprint(hunt);
  const autoEscalation = mode === HUNT_RUN_MODE_EXECUTE
    ? request.autoEscalation ?? (HUNT_RUN_AUTONOMOUS_TRIGGERS.includes(request.trigger) || hunt.escalate_manual_runs === true)
    : null;
  const unresolvedTechniques = targets.length > 0 && mode === HUNT_RUN_MODE_EXECUTE ? await findRunUnresolvedTechniques(context, hunt) : [];
  // Taken before any run is published: a run its connector completes during the dispatch records a later date
  const queuedAt = now();
  const createdAccess: HuntRunAccess[] = [];
  const notCreatedOn: string[] = [];
  let dispatchBudget = request.dispatchLimit ?? Number.POSITIVE_INFINITY;
  for (let index = 0; index < targets.length; index += 1) {
    const { connector, securityPlatform, restrictions } = targets[index];
    let windowStart = fullWindowStart;
    let continuesRunId: string | null = request.continuesRunId ?? null;
    if (incremental) {
      // A lookup that fails searches the full time window: a run is never lost for it
      const previous = await findLastCompletedHuntRun(context, hunt.internal_id, securityPlatform?.internal_id ?? null, logicFingerprint).catch((error) => {
        logApp.warn('[OPENCTI-MODULE] Hunt run previous window lookup failed, the full time window is searched', { cause: error, huntId: hunt.internal_id });
        return null;
      });
      const window = computeHuntRunWindow(windowEnd, hours, HUNT_CONFIG.scheduleLookbackMinutes, previous?.time_window_end);
      windowStart = window.start;
      continuesRunId = window.continued && previous ? previous.internal_id : null;
    }
    const runInput = {
      hunt_id: hunt.internal_id,
      hunt_run_status: HUNT_RUN_STATUS_QUEUED,
      hunt_run_trigger: request.trigger,
      hunt_run_mode: mode,
      security_platform_id: securityPlatform?.internal_id ?? null,
      connector_id: connector.internal_id,
      connector_name: connector.name,
      connector_user_id: connector.connector_user_id ?? null,
      time_window_start: windowStart.toISOString(),
      time_window_end: windowEnd.toISOString(),
      continues_run_id: continuesRunId,
      verdict: HUNT_VERDICT_PENDING,
      attempt: Math.max(1, request.attempt ?? 1),
      retry_of: request.retryOf ?? null,
      hunt_logic_fingerprint: logicFingerprint,
      auto_escalation: autoEscalation,
      unresolved_techniques: unresolvedTechniques,
      aev_inject_id: request.aevInjectId ?? null,
      security_coverage_id: request.securityCoverageId ?? null,
      technique_id: request.techniqueId ?? null,
      triggered_by: request.triggeredBy ?? request.requester?.id ?? HUNT_MANAGER_USER.id,
      objectMarking: restrictions.objectMarking,
      objectOrganization: restrictions.objectOrganization,
      ...(request.playbook ? {
        playbook_id: request.playbook.playbookId,
        playbook_execution_id: request.playbook.executionId,
        playbook_step_id: request.playbook.stepId,
        playbook_instance_id: request.playbook.instanceId ?? null,
        playbook_leader: false,
        playbook_context: null,
      } : {}),
    };
    let run: BasicStoreEntityHuntRun;
    try {
      run = await createEntity(context, HUNT_MANAGER_USER, runInput, ENTITY_TYPE_HUNT_RUN) as BasicStoreEntityHuntRun;
    } catch (error) {
      // Once runs exist, failing would make an automatic trigger create them again at the next tick: they are kept and
      // returned. A platform left without a run catches up at its next recurring run, which searches from its last one
      if (runs.length === 0) {
        throw error;
      }
      logApp.warn('[OPENCTI-MODULE] Hunt run creation interrupted, the runs already created are kept', {
        cause: error,
        huntId: hunt.internal_id,
        created: runs.length,
        targets: targets.length,
      });
      notCreatedOn.push(...targets.slice(index).map((target) => target.securityPlatform?.name ?? target.connector.name));
      break;
    }
    runs.push(run);
    createdAccess.push({ [RELATION_OBJECT_MARKING]: restrictions.objectMarking, [RELATION_GRANTED_TO]: restrictions.objectOrganization });
    addHuntRunCount(request.trigger);
    if (request.dispatch !== false && dispatchBudget > 0) {
      dispatchBudget -= 1;
      try {
        await dispatchHuntRun(context, run, hunt);
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Hunt run dispatch failed, the hunt manager will retry', { cause: error, runId: run.internal_id });
      }
    }
  }
  if (runs.length > 0 && request.playbook?.context) {
    runs[0] = await designateHuntPlaybookLeader(context, runs[0], request.playbook.context);
  }
  if (runs.length > 0 && mode === HUNT_RUN_MODE_EXECUTE) {
    // Never written over the statistics of a run finalized meanwhile; the runs exist, a failure here never fails them
    await recordHuntRunSummary(context, hunt, createdAccess, { last_run_at: queuedAt, last_run_status: HUNT_RUN_STATUS_QUEUED })
      .catch((error) => logApp.warn('[OPENCTI-MODULE] Hunt last run information not recorded', { cause: error, huntId: hunt.internal_id }));
  }
  return { runs, notCreatedOn };
};

const partialHuntRunsError = (hunt: BasicStoreEntityHunt, creation: HuntRunCreation) => {
  const total = creation.runs.length + creation.notCreatedOn.length;
  return FunctionalError(
    `The hunt started on ${creation.runs.length} of ${total} security platforms: its runs could not be created on ${creation.notCreatedOn.join(', ')}, run it again on them`,
    { huntId: hunt.internal_id, runIds: creation.runs.map((run) => run.internal_id) },
  );
};

/**
 * Creates one queued run per target connector and dispatches it when the budget allows (the hunt manager
 * dispatches the deferred ones). Runs are created by the hunt manager identity with the markings and organizations
 * of both the hunt and the target security platform, the human or system at the origin of the run is kept in triggered_by.
 * When the creation is interrupted, a recurring trigger returns the runs created, and a one-shot trigger (manual,
 * playbook), which has no next run to catch up the others, fails once they are kept.
 */
export const createHuntRuns = async (context: AuthContext, hunt: BasicStoreEntityHunt, request: HuntRunRequest): Promise<BasicStoreEntityHuntRun[]> => {
  const creation = await createHuntRunsOnTargets(context, hunt, request);
  if (creation.notCreatedOn.length > 0 && !HUNT_RUN_INCREMENTAL_TRIGGERS.includes(request.trigger)) {
    throw partialHuntRunsError(hunt, creation);
  }
  return creation.runs;
};

/**
 * Hands the continuation of a playbook step to a run of the step once every run of the step exists: the hunt manager
 * resumes the step from its leader as soon as the runs it finds are settled, so a leader named while runs are still
 * being created could resume the step without the later ones.
 */
export const designateHuntPlaybookLeader = async (context: AuthContext, run: BasicStoreEntityHuntRun, playbookContext: HuntPlaybookContext) => {
  const { element } = await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, {
    playbook_leader: true,
    playbook_context: JSON.stringify(playbookContext),
  });
  return element as unknown as BasicStoreEntityHuntRun;
};

export const startHuntRuns = async (
  context: AuthContext,
  user: AuthUser,
  huntId: string,
  input: { security_platform_ids?: string[] | null; time_window_hours?: number | null } | null | undefined,
) => {
  const hunt = await storeLoadById<BasicStoreEntityHunt>(context, user, huntId, ENTITY_TYPE_HUNT);
  if (!hunt) {
    throw ResourceNotFoundError('Hunt cannot be found', { huntId });
  }
  await checkHuntEditAccess(context, user, hunt);
  // A logic its translation preview or a run already failed to translate for good fails again: refused before any
  // connector slot or daily run is spent on it
  const translation = await findHuntTranslation(context, user, hunt, input?.security_platform_ids ?? []);
  if (translation?.state === 'failed') {
    const { template, values } = huntTranslationMessage(translation);
    throw FunctionalError(`The hunt cannot run: ${renderHuntMessage(template, values)}`, { huntId, runId: translation.run.internal_id });
  }
  const creation = await createHuntRunsOnTargets(context, hunt, {
    trigger: 'manual',
    securityPlatformIds: input?.security_platform_ids ?? [],
    timeWindowHours: input?.time_window_hours,
    triggeredBy: user.id,
    requester: user,
  });
  if (creation.runs.length === 0) {
    throw FunctionalError('No live hunt connector serves a security platform of this hunt you can access', { huntId });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `runs hunt \`${hunt.name}\` on ${creation.runs.length} platform(s)`,
    context_data: { id: hunt.internal_id, entity_type: ENTITY_TYPE_HUNT, input: input ?? {} },
  });
  if (creation.notCreatedOn.length > 0) {
    throw partialHuntRunsError(hunt, creation);
  }
  return creation.runs;
};

export const startHuntPreview = async (context: AuthContext, user: AuthUser, huntId: string, securityPlatformId?: string | null) => {
  const hunt = await storeLoadById<BasicStoreEntityHunt>(context, user, huntId, ENTITY_TYPE_HUNT);
  if (!hunt) {
    throw ResourceNotFoundError('Hunt cannot be found', { huntId });
  }
  await checkHuntEditAccess(context, user, hunt);
  const runs = await createHuntRuns(context, hunt, {
    trigger: HUNT_RUN_TRIGGER_PREVIEW,
    mode: HUNT_RUN_MODE_PREVIEW,
    securityPlatformIds: securityPlatformId ? [securityPlatformId] : [],
    triggeredBy: user.id,
    requester: user,
  });
  if (runs.length === 0) {
    throw FunctionalError('No live hunt connector supporting translation preview serves a platform you can access', { huntId, securityPlatformId });
  }
  return runs[0];
};

/**
 * The translation preview of an activated hunt whose current logic no run has translated yet: its result reaches the
 * translation item of the readiness of the hunt. Best effort, the activation never depends on it: a hunt without a
 * preview connector on its scope is activated all the same.
 */
export const startHuntTranslationCheck = async (context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt) => {
  if (context.draft_context || hunt.hunt_type === HUNT_TYPE_INDICATORS) {
    return null;
  }
  try {
    if (await findHuntTranslation(context, user, hunt)) {
      return null;
    }
    const runs = await createHuntRuns(context, hunt, { trigger: HUNT_RUN_TRIGGER_PREVIEW, mode: HUNT_RUN_MODE_PREVIEW, triggeredBy: user.id, requester: user });
    return runs[0] ?? null;
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Hunt translation check at activation skipped', { cause: error, huntId: hunt.internal_id });
    return null;
  }
};

// endregion

// region completion
// Exponential backoff of automatic retries: retry_backoff_minutes, then twice as long at each attempt
export const computeRetryAt = (attempt: number, from = Date.now()) => {
  const backoff = HUNT_CONFIG.retryBackoffMinutes * (2 ** (Math.max(1, attempt) - 1));
  return new Date(from + backoff * 60000).toISOString();
};

export const computeAutomaticVerdict = (run: BasicStoreEntityHuntRun): string => {
  // A run that failed for good searched nothing: it is left without a verdict, never inconclusive
  if (isTerminalHuntRunFailure(run)) {
    return HUNT_VERDICT_PENDING;
  }
  if (run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    return HUNT_VERDICT_INCONCLUSIVE;
  }
  if ((run.hits_count ?? 0) > 0) {
    return HUNT_VERDICT_PENDING;
  }
  // No hit proves nothing unless the results are known complete: partial (shard failures, partial answers, exhausted
  // budget), of unknown completeness, or values of an indicator hunt the platform could not look up
  return run.results_truncated === false && !hasUnsearchedIoc(run.ioc_results) ? HUNT_VERDICT_BENIGN : HUNT_VERDICT_INCONCLUSIVE;
};

/** The run of a `cti.hunt_triage` request. */
export const huntTriageRunPayload = (run: BasicStoreEntityHuntRun, securityPlatformName: string | undefined) => ({
  id: run.internal_id,
  hits_count: run.hits_count ?? 0,
  // Unknown (null) when the connector does not count the entities of its hits
  distinct_entities: run.distinct_entities ?? null,
  // Partial (true), complete (false) or unknown (null): only complete results let a run without hits be benign
  results_truncated: run.results_truncated ?? null,
  time_window: { start: run.time_window_start, end: run.time_window_end },
  security_platform: securityPlatformName ?? HUNT_PLATFORM_INTERNET,
  translated_query: run.translated_query ?? '',
  evidence_sample: run.evidence_sample ?? [],
  hits_sample: run.hits_sample ?? [],
  hit_dates: { first: run.first_hit_at ?? null, last: run.last_hit_at ?? null },
});

/**
 * Triage of a run by the hunt triage agent. `reader` reads what the payload carries: the user asking for a manual
 * triage, so that nothing this user cannot see reaches the agent, or the hunt manager for the automatic triage.
 */
export const triageHuntRunWithAgent = async (
  context: AuthContext,
  reader: AuthUser,
  run: BasicStoreEntityHuntRun,
  hunt: BasicStoreEntityHunt,
  jwtUserId?: string,
) => {
  const jwtUser = await resolveAgentJwtUser(jwtUserId);
  const history = await topEntitiesList<BasicStoreEntityHuntRun>(context, reader, [ENTITY_TYPE_HUNT_RUN], {
    first: TRIAGE_HISTORY_SIZE,
    orderBy: 'completed_at',
    orderMode: OrderingMode.Desc,
    filters: {
      mode: FilterMode.And,
      filters: [
        { key: ['hunt_id'], values: [hunt.internal_id] },
        { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_COMPLETED] },
        { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
        { key: ['id'], values: [run.internal_id], operator: FilterOperator.NotEq },
      ],
      filterGroups: [],
    },
    noFiltersChecking: true,
  });
  const [techniques, targets, securityPlatform] = await Promise.all([
    hunt[RELATION_HUNT_TECHNIQUES]?.length ? findByIds<BasicStoreEntity & { x_mitre_id?: string }>(context, reader, hunt[RELATION_HUNT_TECHNIQUES] ?? []) : [],
    hunt[RELATION_HUNT_TARGETS]?.length ? findByIds<BasicStoreEntity>(context, reader, hunt[RELATION_HUNT_TARGETS] ?? []) : [],
    run.security_platform_id ? internalLoadById<BasicStoreEntity>(context, reader, run.security_platform_id) : null,
  ]);
  const payload = {
    task: 'hunt_triage',
    hunt: {
      id: hunt.internal_id,
      name: hunt.name,
      hypothesis: hunt.hypothesis ?? '',
      sigma_rule: hunt.sigma_rule ?? '',
      benign_patterns: hunt.benign_patterns ?? [],
      escalation_threshold: hunt.escalation_threshold,
      techniques: techniques.map((technique) => ({ x_mitre_id: technique.x_mitre_id ?? null, name: technique.name })),
      targets: targets.map((target) => ({ name: target.name, entity_type: target.entity_type })),
    },
    run: huntTriageRunPayload(run, securityPlatform?.name),
    history: history.map((previous) => ({ id: previous.internal_id, completed_at: previous.completed_at, hits_count: previous.hits_count ?? 0, verdict: previous.verdict })),
  };
  const { slug, answer } = await callHuntAgent(HUNT_TRIAGE_INTENT, jwtUser, payload);
  const triage = validateHuntTriageResult(answer);
  addHuntTriageCount();
  const { element } = await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, {
    verdict_proposal: triage.verdict,
    verdict_proposal_confidence: triage.confidence,
    verdict_proposal_rationale: triage.rationale,
    verdict_proposal_agent: slug,
    incident_proposal: triage.incident ? JSON.stringify(triage.incident) : null,
  });
  return element as unknown as BasicStoreEntityHuntRun;
};

const patchHuntRun = async (context: AuthContext, run: BasicStoreEntityHuntRun, patch: Record<string, unknown>) => {
  const { element } = await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, patch);
  return element as unknown as BasicStoreEntityHuntRun;
};

/**
 * Whether a run opens an incident draft by itself above the escalation threshold, as decided at its creation. A run
 * created before the decision was recorded escalated whatever started it, and keeps doing so.
 */
export const isAutoEscalatedHuntRun = (run: Pick<BasicStoreEntityHuntRun, 'auto_escalation'>) => run.auto_escalation !== false;

/**
 * A terminated executed run is finalized once its automatic verdict is recorded (verdict_source set, by finalization or
 * by an analyst). A terminated run without it stopped before the end of its finalization and is finalized again.
 */
export const isHuntRunFinalized = (run: Pick<BasicStoreEntityHuntRun, 'hunt_run_mode' | 'hunt_run_status' | 'verdict_source'>) => {
  return run.hunt_run_mode !== HUNT_RUN_MODE_EXECUTE || !HUNT_RUN_FINALIZABLE_STATUSES.includes(run.hunt_run_status) || !!run.verdict_source;
};

const HUNT_INCIDENT_LOCK = 'hunt_incident';

// Each run escalates under its own transition lock: the runs of a hunt on a platform find or open their incident, and
// record it, one at a time, so that runs escalated together continue the incident the first one opens
const withHuntIncidentLock = <T>(run: BasicStoreEntityHuntRun, action: () => Promise<T>): Promise<T> => {
  return withHuntLock(`${HUNT_INCIDENT_LOCK}_${run.hunt_id}_${run.security_platform_id ?? HUNT_PLATFORM_INTERNET}`, action);
};

/**
 * The incident of a run: the hits go to the incident still open from a previous run of the hunt on the same platform
 * (in its draft when not validated yet), else a new incident draft is opened. A draft recorded by an interrupted
 * finalization is reused rather than doubled. The run records the incident, and whether it continued an open one.
 */
const escalateHuntRun = async (
  context: AuthContext,
  hunt: BasicStoreEntityHunt,
  run: BasicStoreEntityHuntRun,
  proposal: ReturnType<typeof parseIncidentProposal>,
): Promise<BasicStoreEntityHuntRun> => withHuntIncidentLock(run, async () => {
  const open: OpenHuntIncident | null = run.draft_id ? null : await findOpenHuntIncident(context, run);
  if (open) {
    await continueHuntIncident(context, hunt, run, open);
    return patchHuntRun(context, run, { incident_id: open.incidentId, draft_id: open.draftId, incident_continued: true });
  }
  let current = run;
  if (!current.draft_id) {
    const draftId = await createHuntIncidentWorkspace(context, current);
    current = await patchHuntRun(context, current, { draft_id: draftId });
  }
  const incidentId = await createHuntIncidentInWorkspace(context, hunt, current, proposal, current.draft_id as string);
  return patchHuntRun(context, current, { incident_id: incidentId, incident_continued: false });
});

/**
 * Post-completion of a run: the sightings of the hunt, the incident above the escalation threshold of new hits (a new
 * draft, or the incident still open from a previous run), hunt statistics, Security Coverage
 * write-back for emulation runs, then the automatic verdict, which marks the run finalized. Every step is idempotent
 * (the draft and incident ids are recorded as soon as they exist, older runs never overwrite the statistics of a newer
 * one, the coverage write-back merges): when one fails, the run stays unfinalized and a later attempt completes it.
 * `force` records the verdict whatever failed, for a run whose finalization keeps failing.
 */
const finalizeHuntRun = async (context: AuthContext, run: BasicStoreEntityHuntRun, hunt: BasicStoreEntityHunt, force = false) => {
  if (run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW) {
    return run;
  }
  let current = run;
  let complete = true;
  // A failed step is attempted again by the hunt manager, unless the finalization is forced: its work is then lost
  const stepFailed = (message: string, error: unknown) => {
    complete = false;
    const meta = { cause: error, runId: current.internal_id };
    if (force) {
      logApp.error(`${message}, given up`, meta);
    } else {
      logApp.warn(`${message}, attempted again by the hunt manager`, meta);
    }
  };
  // The hits as knowledge first: the incident relates to them
  if (current.hunt_run_status === HUNT_RUN_STATUS_COMPLETED && (current.hits_sample ?? []).length > 0 && (current.hit_observation_ids ?? []).length === 0) {
    try {
      const { observedDataIds, observableIds } = await createHuntHitObservations(context, hunt, current);
      const observationIds = [...observedDataIds, ...observableIds];
      if (observationIds.length > 0) {
        const resultIds = Array.from(new Set([...(current.result_ids ?? []), ...observedDataIds])).slice(0, HUNT_RUN_RESULT_IDS_MAX);
        current = await patchHuntRun(context, current, { hit_observation_ids: observationIds, result_ids: resultIds });
      }
    } catch (error) {
      stepFailed('[OPENCTI-MODULE] Hunt hit observations creation failed', error);
    }
  }
  // One sighting per hunt, sighted object and platform, updated in place: never a sighting per run
  if (current.hunt_run_status === HUNT_RUN_STATUS_COMPLETED && (current.hits_count ?? 0) > 0) {
    try {
      const sightings = await upsertHuntSightings(context, hunt, current);
      if (sightings.ids.length > 0) {
        const resultIds = Array.from(new Set([...(current.result_ids ?? []), ...sightings.ids])).slice(0, HUNT_RUN_RESULT_IDS_MAX);
        current = await patchHuntRun(context, current, { result_ids: resultIds, sightings_created_count: current.sightings_created_count ?? sightings.created });
      }
    } catch (error) {
      stepFailed('[OPENCTI-MODULE] Hunt sightings update failed', error);
    }
  }
  // Only hits never seen before escalate: a standing hunt above its threshold on known activity opens nothing new. A
  // run started by hand escalates only when its hunt asks for it: otherwise the analyst opens the incident with a true
  // positive verdict, never before reading the hits
  const newHits = huntRunNewHits(current);
  if (current.hunt_run_status === HUNT_RUN_STATUS_COMPLETED && isAutoEscalatedHuntRun(current)
    && newHits > 0 && newHits >= hunt.escalation_threshold && !current.incident_id) {
    try {
      current = await escalateHuntRun(context, hunt, current, null);
    } catch (error) {
      stepFailed('[OPENCTI-MODULE] Hunt incident draft creation failed', error);
    }
  }
  try {
    await recordHuntRunSummary(context, hunt, [current], {
      last_run_at: current.completed_at ?? now(),
      last_run_status: current.hunt_run_status,
      last_hits_count: current.hits_count ?? 0,
      last_new_hits_count: newHits,
    });
  } catch (error) {
    stepFailed('[OPENCTI-MODULE] Hunt statistics update failed', error);
  }
  if (current.hunt_run_status === HUNT_RUN_STATUS_COMPLETED) {
    try {
      await writeHuntCoverageResult(context, current);
    } catch (error) {
      stepFailed('[OPENCTI-MODULE] Hunt coverage write-back failed', error);
    }
  }
  if (!complete && !force) {
    return current;
  }
  return patchHuntRun(context, current, { verdict: computeAutomaticVerdict(current), verdict_source: HUNT_VERDICT_SOURCE_AUTO });
};

// Automatic triage of runs with hits never blocks the connector report
const scheduleAutomaticTriage = (context: AuthContext, run: BasicStoreEntityHuntRun, hunt: BasicStoreEntityHunt) => {
  if (run.hunt_run_mode !== HUNT_RUN_MODE_EXECUTE || run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED || (run.hits_count ?? 0) === 0) {
    return;
  }
  isEnterpriseEdition(context)
    .then((available) => (available ? triageHuntRunWithAgent(context, HUNT_MANAGER_USER, run, hunt) : null))
    .catch((error) => logApp.warn('[OPENCTI-MODULE] Automatic hunt triage skipped', { cause: error, runId: run.internal_id }));
};

const HUNT_RUN_TRANSITION_LOCK = 'hunt_run_transition';

// Connector reports and manager expiries of a run are serialized, the run is read again under the lock so that a run
// is finalized (verdict, statistics, retry schedule, notification) only once
const withHuntRunTransition = async <T>(
  context: AuthContext,
  runId: string,
  transition: (current: BasicStoreEntityHuntRun) => Promise<T>,
): Promise<T> => {
  return withHuntLock(`${HUNT_RUN_TRANSITION_LOCK}_${runId}`, async () => {
    const current = await findHuntRunById(context, HUNT_MANAGER_USER, runId);
    if (!current) {
      throw ResourceNotFoundError('Hunt run cannot be found', { runId });
    }
    return transition(current);
  });
};

/**
 * Releases the dispatch reservation of a run whose publication was never recorded: the platform stopped between its
 * reservation and the publication of its message, or could not record the date of a publication. The run is read again
 * under its transition lock, the one connector reports take: a run reported meanwhile, published, reserved again or
 * holding another work is left as it is. True when released.
 */
export const releaseUnpublishedHuntRun = async (context: AuthContext, run: BasicStoreEntityHuntRun, reservedBefore: string): Promise<boolean> => {
  return withHuntRunTransition(context, run.internal_id, async (current) => {
    const stale = current.hunt_run_status === HUNT_RUN_STATUS_QUEUED
      && !current.published_at
      && !!current.dispatched_at
      && new Date(current.dispatched_at).getTime() <= new Date(reservedBefore).getTime()
      && (current.work_id ?? null) === (run.work_id ?? null);
    if (!stale) {
      return false;
    }
    // The run keeps its work: a message published before its date could be recorded still reports to that work, and the
    // run is published again under it (dispatchHuntRun), so a second report finds the run settled
    await patchAttribute(context, HUNT_MANAGER_USER, current.internal_id, ENTITY_TYPE_HUNT_RUN, { dispatched_at: null });
    return true;
  });
};

/**
 * Cancels a run whose hunt or hunt connector was deleted, under its transition lock: a queued or running run ends
 * cancelled, which frees its connector slot, and the automatic retry planned on a terminated run is dropped. A cancelled
 * run gets no verdict, never counts in the statistics and is never retried. Returns the run when it changed.
 */
export const cancelHuntRun = async (context: AuthContext, runId: string, reason: string): Promise<BasicStoreEntityHuntRun | null> => {
  const updated = await withHuntRunTransition(context, runId, async (current) => {
    if (HUNT_RUN_ACTIVE_STATUSES.includes(current.hunt_run_status)) {
      return patchHuntRun(context, current, { hunt_run_status: HUNT_RUN_STATUS_CANCELLED, completed_at: now(), error_message: reason, next_retry_at: null });
    }
    return current.next_retry_at ? patchHuntRun(context, current, { next_retry_at: null }) : null;
  });
  return updated ? notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, updated, HUNT_MANAGER_USER) : null;
};

/**
 * Cancels the runs matching the filters that still wait, run or plan a retry: the runs of a deleted hunt or of a deleted
 * hunt connector. A failure on one run is logged, the hunt manager cancels it at a later pass. Returns the runs changed.
 */
export const cancelHuntRuns = async (context: AuthContext, filters: FilterGroup['filters'], reason: string): Promise<number> => {
  const runs = await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    filters: {
      mode: FilterMode.And,
      filters,
      filterGroups: [{
        mode: FilterMode.Or,
        filters: [
          { key: ['hunt_run_status'], values: HUNT_RUN_ACTIVE_STATUSES },
          { key: ['next_retry_at'], values: [], operator: FilterOperator.NotNil },
        ],
        filterGroups: [],
      }],
    },
    noFiltersChecking: true,
  });
  let cancelled = 0;
  for (let index = 0; index < runs.length; index += 1) {
    try {
      if (await cancelHuntRun(context, runs[index].internal_id, reason)) {
        cancelled += 1;
      }
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt run cannot be cancelled, the hunt manager cancels it at a later pass', { cause: error, runId: runs[index].internal_id });
    }
  }
  return cancelled;
};

/** Cancels the runs of a deleted hunt. Never fails the deletion: the hunt manager cancels what is left. */
export const cancelDeletedHuntRuns = async (context: AuthContext, huntId: string) => {
  try {
    return await cancelHuntRuns(context, [{ key: ['hunt_id'], values: [huntId] }], HUNT_MESSAGES.runCancelledHuntDeleted);
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Runs of a deleted hunt cannot be cancelled, the hunt manager cancels them at a later pass', { cause: error, huntId });
    return 0;
  }
};

/** Cancels the runs of a deleted hunt connector, so that a connector registered again under its id inherits none. */
export const cancelDeletedHuntConnectorRuns = async (context: AuthContext, connectorId: string) => {
  try {
    return await cancelHuntRuns(context, [{ key: ['connector_id'], values: [connectorId] }], HUNT_MESSAGES.runCancelledConnectorDeleted);
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Runs of a deleted hunt connector cannot be cancelled, the hunt manager cancels them at a later pass', { cause: error, connectorId });
    return 0;
  }
};

/**
 * Cancels the runs of a hunt connector registered again against another security platform (or the internet): created for
 * the former one, they would execute on the new one with their hits attributed to the former. Never fails the registration.
 */
const cancelReboundHuntConnectorRuns = async (context: AuthContext, connectorId: string, securityPlatformId: string | null) => {
  const platformFilter = securityPlatformId
    ? { key: ['security_platform_id'], values: [securityPlatformId], operator: FilterOperator.NotEq }
    : { key: ['security_platform_id'], values: [], operator: FilterOperator.NotNil };
  try {
    return await cancelHuntRuns(context, [{ key: ['connector_id'], values: [connectorId] }, platformFilter], HUNT_MESSAGES.runCancelledConnectorRebound);
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Runs of a hunt connector bound to another platform cannot be cancelled, the hunt manager cancels them at a later pass', { cause: error, connectorId });
    return 0;
  }
};

/**
 * The next attempt already created for a terminated run: the retry that names it in retry_of. Two runs sharing their
 * hunt, connector, window and attempt (two playbook executions, two emulations) each get their own replacement.
 */
const findHuntRunReplacement = async (context: AuthContext, run: BasicStoreEntityHuntRun) => {
  const filters = [
    { key: ['hunt_id'], values: [run.hunt_id] },
    { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_RETRY] },
    { key: ['retry_of'], values: [run.internal_id] },
  ];
  const retries = await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    filters: { mode: FilterMode.And, filters, filterGroups: [] },
    noFiltersChecking: true,
  });
  return retries.find((retry) => retry.retry_of === run.internal_id) ?? null;
};

export interface HuntRunReplacementOptions {
  // Automatic retries only replace a run whose retry is planned; a manual retry replaces it anyway
  automatic: boolean;
  triggeredBy?: string | null;
  requester?: AuthUser;
}

/**
 * Replaces a terminated run by its next attempt on the same connector and window, under the transition lock of the
 * run: the check of an existing replacement and its creation are atomic, so concurrent retries (manual ones, or a
 * manual one and the hunt manager) create a single next attempt and the later ones get it back with `created: false`.
 * The planned automatic retry is consumed once the replacement exists. A crash between the creation and the
 * consumption is caught up by the next retry, which finds the replacement.
 */
export const replaceHuntRun = async (context: AuthContext, hunt: BasicStoreEntityHunt, runId: string, options: HuntRunReplacementOptions) => {
  return withHuntRunTransition(context, runId, async (run) => {
    const planned = !!run.next_retry_at;
    const consume = async () => {
      if (planned) {
        await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: null });
      }
    };
    const existing = await findHuntRunReplacement(context, run);
    if (existing) {
      await consume();
      return { run, planned, replacement: existing, created: false };
    }
    if (options.automatic && !planned) {
      return { run, planned, replacement: null, created: false };
    }
    const runs = await createHuntRuns(context, hunt, {
      trigger: HUNT_RUN_TRIGGER_RETRY,
      mode: run.hunt_run_mode,
      securityPlatformIds: run.security_platform_id ? [run.security_platform_id] : [],
      connectorIds: run.connector_id ? [run.connector_id] : [],
      windowStart: run.time_window_start,
      windowEnd: run.time_window_end,
      aevInjectId: run.aev_inject_id,
      securityCoverageId: run.security_coverage_id,
      techniqueId: run.technique_id,
      triggeredBy: options.triggeredBy ?? run.triggered_by,
      requester: options.requester,
      attempt: (run.attempt ?? 1) + 1,
      retryOf: run.internal_id,
      continuesRunId: run.continues_run_id ?? null,
      autoEscalation: isAutoEscalatedHuntRun(run),
      // A planned retry keeps the run in its playbook step, which waits on it
      playbook: planned && run.playbook_id && run.playbook_execution_id && run.playbook_step_id
        ? { playbookId: run.playbook_id, executionId: run.playbook_execution_id, stepId: run.playbook_step_id, instanceId: run.playbook_instance_id }
        : null,
    });
    if (runs.length > 0) {
      await consume();
    }
    return { run, planned, replacement: runs[0] ?? null, created: runs.length > 0 };
  });
};

/**
 * Manual retry of a terminated run: the next attempt on the same connector and window. It replaces the automatic retry
 * planned on the run, if any, which stays planned when the replacement cannot be created. A run already replaced
 * returns its replacement.
 */
export const retryHuntRun = async (context: AuthContext, user: AuthUser, runId: string) => {
  const reachable = await findHuntRunById(context, user, runId);
  if (!reachable) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  if (!HUNT_RUN_TERMINAL_STATUSES.includes(reachable.hunt_run_status)) {
    throw FunctionalError('Only a terminated run can be retried', { runId, status: reachable.hunt_run_status });
  }
  if (reachable.hunt_run_status === HUNT_RUN_STATUS_CANCELLED) {
    throw FunctionalError(`A cancelled run is not retried: ${reachable.error_message ?? 'its hunt or its hunt connector was deleted'}`, { runId });
  }
  const hunt = await loadHuntForRunEdit(context, user, reachable);
  const { replacement } = await replaceHuntRun(context, hunt, reachable.internal_id, { automatic: false, triggeredBy: user.id, requester: user });
  if (!replacement) {
    throw FunctionalError('The hunt connector of this run is not alive anymore', { runId, connectorId: reachable.connector_id });
  }
  return replacement;
};

/**
 * The values of an indicator hunt run, each with the indicators and observables it comes from that the user can read:
 * all the sources of the run are read at once.
 */
export const resolveHuntRunIocResults = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const results = run.ioc_results ?? [];
  if (results.length === 0) {
    return run.ioc_results ?? null;
  }
  const sourceIds = Array.from(new Set(results.flatMap((result) => result.source_ids ?? [])));
  const sources = await findByIds<BasicStoreObject>(context, user, sourceIds);
  const sourcesById = new Map(sources.map((source) => [source.internal_id, source]));
  return results.map((result) => ({
    ...result,
    hosts: result.hosts ?? [],
    sources: (result.source_ids ?? []).map((id) => sourcesById.get(id)).filter((source) => !!source),
    deployed: (result.deployment_ids ?? []).length > 0,
  }));
};

/**
 * Whether the user acts as the hunt connector the run was dispatched to. Several hunt connectors can run as the same
 * user: the work of the dispatch, which only the connector that received the run knows, binds the call to that
 * connector. The run stores its work before the connector receives it, so a run without work was never handed to any
 * connector. A connector registered again as another user no longer acts on the runs dispatched to its former user.
 */
export const isHuntRunConnectorCall = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun, workId: string | null | undefined) => {
  if (!run.work_id || workId !== run.work_id || !run.connector_user_id || run.connector_user_id !== user.id) {
    return false;
  }
  const connectors = await listHuntConnectors(context, false);
  const connector = connectors.find((c) => c.internal_id === run.connector_id);
  return connector?.connector_user_id === user.id;
};

/** The keys of the values each hit of an indicator run holds, by hit key, from the keys each value result reports. */
export const huntIocKeysByHit = (iocResults: ReadonlyArray<{ key?: string | null; hit_keys?: ReadonlyArray<string> | null }> | null | undefined) => {
  const byHit = new Map<string, string[]>();
  (iocResults ?? []).forEach((result) => {
    const iocKey = typeof result.key === 'string' ? result.key : '';
    (sanitizeHitKeys(result.hit_keys) ?? []).forEach((hitKey) => {
      if (iocKey.length > 0) {
        byHit.set(hitKey, Array.from(new Set([...(byHit.get(hitKey) ?? []), iocKey])));
      }
    });
  });
  return byHit;
};

/**
 * New and recurring hits of a completed run, from the hit keys its connector reports, matched against the hits already
 * known for the hunt on the platform of the run (which then knows them too). A connector that reports no key (an older
 * one, or a lookup that returns counts) or keys that do not identify the hits of the run makes every hit new, and so
 * does a ledger that cannot be read: the run says so with hits_identified.
 */
const recordReportedHits = async (
  context: AuthContext,
  run: BasicStoreEntityHuntRun,
  input: Pick<HuntRunReportInput, 'hit_keys' | 'ioc_results'>,
  hits: { count: number; sampledKeys: ReadonlyArray<string | null | undefined> },
  reportedAt: string,
) => {
  const unidentified = { hits_identified: false, hits_new_count: hits.count, hits_recurring_count: 0 };
  const iocKeysByHit = huntIocKeysByHit(input.ioc_results as never);
  const keys = identifyingHitKeys(input.hit_keys, { hitsCount: hits.count, sampledKeys: hits.sampledKeys, extraKeys: [...iocKeysByHit.keys()] });
  if (keys === null) {
    if (Array.isArray(input.hit_keys)) {
      logApp.warn('[OPENCTI-MODULE] Hunt hit keys do not identify the hits of the run, every hit counts as new', { runId: run.internal_id, hitsCount: hits.count });
    }
    return unidentified;
  }
  try {
    const { newCount, recurringCount } = await recordHuntHits(context, {
      huntId: run.hunt_id,
      securityPlatformId: run.security_platform_id,
      runId: run.internal_id,
      keys,
      iocKeysByHit,
      seenAt: reportedAt,
    });
    const { newHits, recurringHits } = splitHitsByKeys(hits.count, newCount, recurringCount);
    return { hits_identified: true, hits_new_count: newHits, hits_recurring_count: recurringHits };
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Hunt known hits could not be matched, every hit of the run counts as new', { cause: error, runId: run.internal_id });
    return unidentified;
  }
};

/**
 * Report of a run by its hunt connector (contract section 5).
 */
export const reportHuntRun = async (context: AuthContext, user: AuthUser, runId: string, input: HuntRunReportInput) => {
  const reported = await findHuntRunById(context, HUNT_MANAGER_USER, runId);
  if (!reported) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  if (!isBypassUser(user) && !await isHuntRunConnectorCall(context, user, reported, input.work_id ?? context.workId)) {
    throw ForbiddenAccess('Only the hunt connector the run was dispatched to can report it', { runId });
  }
  const status = input.status as string;
  if (![HUNT_RUN_STATUS_RUNNING, HUNT_RUN_STATUS_COMPLETED, HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT].includes(status)) {
    throw FunctionalError('A hunt connector can only report a running, completed, failed or timeout status', { runId, status });
  }
  const updated = await withHuntRunTransition(context, reported.internal_id, (run) => applyHuntRunReport(context, run, status, input));
  return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, updated, user);
};

const applyHuntRunReport = async (context: AuthContext, run: BasicStoreEntityHuntRun, status: string, input: HuntRunReportInput) => {
  if (HUNT_RUN_TERMINAL_STATUSES.includes(run.hunt_run_status)) {
    // A run cancelled while its connector executed it: the connector gets the reason and sends no knowledge for it
    if (run.hunt_run_status === HUNT_RUN_STATUS_CANCELLED) {
      throw FunctionalError(`The hunt run was cancelled: ${run.error_message ?? 'its hunt or its hunt connector was deleted'}`, { runId: run.internal_id });
    }
    if (isHuntRunFinalized(run)) {
      throw FunctionalError('The hunt run is already terminated', { runId: run.internal_id, status: run.hunt_run_status });
    }
    // The first report terminated the run but its finalization stopped halfway: complete it, the run stays as first reported
    return completeHuntRunFinalization(context, run);
  }
  const reportedAt = now();
  const patch: Record<string, unknown> = { hunt_run_status: status };
  if (!run.started_at) {
    patch.started_at = reportedAt;
  }
  if (typeof input.translated_query === 'string') {
    patch.translated_query = truncate(input.translated_query, TRANSLATED_QUERY_MAX_LENGTH);
  }
  if (typeof input.query_language === 'string') {
    patch.query_language = truncate(input.query_language, 64);
  }
  if (status === HUNT_RUN_STATUS_COMPLETED) {
    patch.completed_at = reportedAt;
    if (run.hunt_run_mode === HUNT_RUN_MODE_EXECUTE) {
      // Evidence attached while the run was running stays with it: the report adds its hits, samples and results to it.
      // Only the reported hits are matched against the known hits, the evidence was matched when it was attached.
      let reportedHits = Math.max(0, Math.round(input.hits_count ?? 0));
      // A connector that does not count the entities of its hits leaves the count unknown, never zero
      patch.distinct_entities = typeof input.distinct_entities === 'number' ? Math.max(0, Math.round(input.distinct_entities)) : null;
      const reportedSample = sanitizeHits(input.hits_sample);
      const hitsSample = mergeHits(run.hits_sample ?? [], reportedSample);
      patch.hits_sample = hitsSample;
      patch.evidence_sample = markMatchedEvidence(mergeEvidence(run.evidence_sample ?? [], sanitizeEvidence(input.evidence_sample)), hitsSample);
      Object.assign(patch, huntHitDates(hitsSample, { first_hit_at: input.first_hit_at, last_hit_at: input.last_hit_at }, run));
      const reportedIds = (input.result_ids ?? []).filter((id) => typeof id === 'string' && STIX_ID_PATTERN.test(id));
      const resultIds = Array.from(new Set([...(run.result_ids ?? []), ...reportedIds]));
      patch.result_ids = resultIds.slice(0, HUNT_RUN_RESULT_IDS_MAX);
      if (Array.isArray(run.ioc_results) && run.ioc_results.length > 0) {
        const iocResults = await linkIocDeployments(context, run, mergeHuntIocResults(run.ioc_results, input.ioc_results ?? []));
        patch.ioc_results = iocResults;
        if (input.hits_count === null || input.hits_count === undefined) {
          reportedHits = countIocHits(iocResults);
        }
      }
      patch.hits_count = (run.hits_count ?? 0) + reportedHits;
      // Results are complete only when the connector says so: a report that omits it leaves the state unknown, and the
      // evidence attached while running may already have cut the results
      const truncated = input.truncated === true || run.results_truncated === true || resultIds.length > HUNT_RUN_RESULT_IDS_MAX;
      patch.results_truncated = truncated ? true : (input.truncated ?? null);
      const sampledKeys = reportedSample.map((hit) => hit.hit_key);
      const reported = await recordReportedHits(context, run, input, { count: reportedHits, sampledKeys }, reportedAt);
      Object.assign(patch, reported, {
        hits_new_count: huntRunNewHits(run) + reported.hits_new_count,
        hits_recurring_count: (run.hits_recurring_count ?? 0) + reported.hits_recurring_count,
      });
    }
    if (typeof input.cost_ms === 'number') {
      patch.cost_ms = Math.max(0, Math.round(input.cost_ms));
    }
  }
  // A timeout is a run the connector stopped at its deadline: same completion path as a failure
  if (status === HUNT_RUN_STATUS_FAILED || status === HUNT_RUN_STATUS_TIMEOUT) {
    patch.completed_at = reportedAt;
    patch.error_message = truncate(input.error ?? (status === HUNT_RUN_STATUS_TIMEOUT ? 'The run exceeded its deadline' : 'Unknown error'), ERROR_MESSAGE_MAX_LENGTH);
    // A failure met again at every attempt (translation, a query the platform rejects) is never retried: each attempt
    // would take a connector slot and a run of the daily quota for the same error
    const deterministic = isDeterministicHuntFailure(status, input.error, input.retryable);
    patch.failure_retryable = !deterministic;
    // Automatic retries with exponential backoff, translation previews are never retried
    if (!deterministic && run.hunt_run_mode === HUNT_RUN_MODE_EXECUTE && run.attempt <= HUNT_CONFIG.maxRetries) {
      patch.next_retry_at = computeRetryAt(run.attempt);
    }
  }
  const { element } = await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, patch);
  let updated = element as unknown as BasicStoreEntityHuntRun;
  if (HUNT_RUN_TERMINAL_STATUSES.includes(status)) {
    const hunt = await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT });
    if (hunt) {
      updated = await finalizeHuntRun(context, updated, hunt);
      scheduleAutomaticTriage(context, updated, hunt);
    }
  }
  return updated;
};

const completeHuntRunFinalization = async (context: AuthContext, run: BasicStoreEntityHuntRun, force = false) => {
  const hunt = await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT });
  if (!hunt) {
    // The run of a deleted hunt is closed without a verdict: nobody triages it and no statistics count it
    return patchHuntRun(context, run, { verdict_source: HUNT_VERDICT_SOURCE_AUTO });
  }
  const finalized = await finalizeHuntRun(context, run, hunt, force);
  if (force && !isHuntRunFinalized(run)) {
    logApp.warn('[OPENCTI-MODULE] Hunt run finalized after repeated failures of its finalization steps', { runId: run.internal_id });
  } else if (isHuntRunFinalized(finalized)) {
    logApp.info('[OPENCTI-MODULE] Hunt run finalization completed after an interruption', { runId: run.internal_id });
  }
  return finalized;
};

/**
 * Finalizes again a terminated run whose finalization stopped halfway (hunt manager reconciliation), under the run
 * transition lock so that it never races a connector report. `force` records the verdict even if a step fails again.
 */
export const reconcileHuntRunFinalization = async (context: AuthContext, unfinalizedRun: BasicStoreEntityHuntRun, force = false) => {
  return withHuntRunTransition(context, unfinalizedRun.internal_id, async (run) => {
    if (isHuntRunFinalized(run)) {
      return run;
    }
    const finalized = await completeHuntRunFinalization(context, run, force);
    return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, finalized, HUNT_MANAGER_USER);
  });
};

/**
 * Terminates a run the platform stopped waiting for (hunt manager): never dispatched in time, or dispatched and not
 * reported within its timeout. Same completion path as a connector failure: verdict, retry schedule, statistics.
 */
export const expireHuntRun = async (context: AuthContext, expiredRun: BasicStoreEntityHuntRun, reason: string) => {
  if (HUNT_RUN_TERMINAL_STATUSES.includes(expiredRun.hunt_run_status)) {
    return expiredRun;
  }
  return withHuntRunTransition(context, expiredRun.internal_id, (run) => applyHuntRunExpiry(context, run, reason));
};

const applyHuntRunExpiry = async (context: AuthContext, run: BasicStoreEntityHuntRun, reason: string) => {
  if (HUNT_RUN_TERMINAL_STATUSES.includes(run.hunt_run_status)) {
    return run;
  }
  const hunt = await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT });
  // A run of a deleted hunt is cancelled, never a timeout with a verdict
  if (!hunt) {
    const cancelled = await patchHuntRun(context, run, {
      hunt_run_status: HUNT_RUN_STATUS_CANCELLED,
      completed_at: now(),
      error_message: HUNT_MESSAGES.runCancelledHuntDeleted,
      next_retry_at: null,
    });
    return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, cancelled, HUNT_MANAGER_USER);
  }
  const patch: Record<string, unknown> = {
    hunt_run_status: HUNT_RUN_STATUS_TIMEOUT,
    completed_at: now(),
    error_message: truncate(reason, ERROR_MESSAGE_MAX_LENGTH),
  };
  // A run that never reached its connector is not retried: its connector is gone or saturated
  if (run.dispatched_at && run.hunt_run_mode === HUNT_RUN_MODE_EXECUTE && run.attempt <= HUNT_CONFIG.maxRetries) {
    patch.next_retry_at = computeRetryAt(run.attempt);
  }
  const updated = await finalizeHuntRun(context, await patchHuntRun(context, run, patch), hunt);
  return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, updated, HUNT_MANAGER_USER);
};
// endregion

// region late evidence
const EVIDENCE_IDS_PER_CALL = 1000;
const EVIDENCE_SOURCE_MAX_LENGTH = 128;
const EVIDENCE_SOURCES_MAX = 20;

/**
 * Statistics and coverage of a finalized completed run whose verdict an analyst or an agent set: they follow its hit
 * count, the verdict stays. Both steps are idempotent; a failure is logged and the next evidence refreshes them again.
 */
const refreshHuntRunOutcome = async (context: AuthContext, run: BasicStoreEntityHuntRun, hunt: BasicStoreEntityHunt) => {
  try {
    await recordHuntRunSummary(context, hunt, [run], {
      last_run_at: run.completed_at ?? now(),
      last_run_status: run.hunt_run_status,
      last_hits_count: run.hits_count ?? 0,
      last_new_hits_count: huntRunNewHits(run),
    });
    await writeHuntCoverageResult(context, run);
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Hunt run outcome refresh after late evidence failed', { cause: error, runId: run.internal_id });
  }
};

/**
 * Evidence found outside the dispatch of a run (a SIEM alert action, a follow-up search, a late result), on any run
 * status: result objects are merged, hits are added, the evidence sample is merged under the platform caps. The status
 * never changes. When hits reach a completed run already finalized, its outcome follows: an automatic verdict is
 * finalized again (verdict, Incident draft above the escalation threshold, hunt statistics, coverage write-back of an
 * emulation run; the hunt manager completes a finalization interrupted by a failing step), while a verdict set by an
 * analyst or an agent is kept and only the statistics and the coverage follow.
 */
export const addHuntRunEvidence = async (context: AuthContext, user: AuthUser, runId: string, input: HuntRunEvidenceAddInput) => {
  const run = await findHuntRunById(context, user, runId);
  if (!run) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  const hunt = await loadHuntForRunEdit(context, user, run);
  if (run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW) {
    throw FunctionalError('A translation preview holds no evidence', { runId });
  }
  const requestedIds = Array.from(new Set((input.result_ids ?? [])
    .filter((id) => typeof id === 'string' && id.trim().length > 0)
    .map((id) => id.trim())));
  if (requestedIds.length === 0 || requestedIds.length > EVIDENCE_IDS_PER_CALL) {
    throw FunctionalError(`Evidence is attached by 1 to ${EVIDENCE_IDS_PER_CALL} result objects`, { count: requestedIds.length });
  }
  // Only objects the caller can read are attached, by their standard ids like the connector reports
  const results = await findByIds<BasicStoreObject>(context, user, requestedIds);
  const knownIds = new Set<string>(results.flatMap((result) => [result.internal_id, result.standard_id, ...(result.x_opencti_stix_ids ?? [])]));
  const unresolved = requestedIds.filter((id) => !knownIds.has(id));
  if (unresolved.length > 0) {
    throw FunctionalError('Evidence objects cannot be found or are not accessible', { unresolved: unresolved.slice(0, 10), count: unresolved.length });
  }
  if (input.security_platform_id) {
    const platform = await storeLoadById<BasicStoreEntitySecurityPlatform>(context, user, input.security_platform_id, ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM);
    if (!platform) {
      throw ResourceNotFoundError('The security platform of the evidence cannot be found', { securityPlatformId: input.security_platform_id });
    }
    if (run.security_platform_id && run.security_platform_id !== platform.internal_id) {
      throw FunctionalError('The evidence was observed on another security platform than the one of the run', { runId });
    }
  }
  const observedAt = input.observed_at ? new Date(input.observed_at) : new Date();
  if (Number.isNaN(observedAt.getTime())) {
    throw FunctionalError('The evidence observation date is invalid', { observedAt: input.observed_at });
  }
  const source = typeof input.source === 'string' && input.source.trim().length > 0 ? truncate(input.source.trim(), EVIDENCE_SOURCE_MAX_LENGTH) : null;
  const addedHits = Math.max(0, Math.round(input.hits_count ?? 0));
  // Merged on the run read again under the transition lock, concurrent evidence never overwrites each other
  const element = await withHuntRunTransition(context, run.internal_id, async (current) => {
    // Late evidence can arrive out of order: the most recent observation is kept
    const previousEvidenceAt = current.last_evidence_at ? new Date(current.last_evidence_at).getTime() : Number.NEGATIVE_INFINITY;
    const lastEvidenceAt = new Date(Math.max(previousEvidenceAt, observedAt.getTime()));
    const resultIds = Array.from(new Set([...(current.result_ids ?? []), ...results.map((result) => result.standard_id)]));
    const hitsSample = mergeHits(current.hits_sample ?? [], sanitizeHits(input.hits_sample));
    // Evidence with hit keys tells its new hits from the known ones and leaves out the hits its run already counted;
    // without keys identifying them, its hits count as new
    let countedHits = addedHits;
    let addedNew = addedHits;
    let addedRecurring = 0;
    const evidenceKeys = identifyingHitKeys(input.hit_keys, { hitsCount: addedHits, sampledKeys: sanitizeHits(input.hits_sample).map((hit) => hit.hit_key) });
    if (evidenceKeys && evidenceKeys.length > 0 && current.hunt_run_mode === HUNT_RUN_MODE_EXECUTE) {
      try {
        const matched = await recordHuntHits(context, {
          huntId: current.hunt_id,
          securityPlatformId: current.security_platform_id,
          runId: current.internal_id,
          keys: evidenceKeys,
          // The hits of this evidence were seen when it was observed, an earlier observation than the last one included
          seenAt: observedAt.toISOString(),
          keepKnown: !await isHuntRunRemembered(context, current),
          uncountedOnly: true,
        });
        // A key can stand for several hits: the hits of the keys left out are left out like the keys
        const uncountedKeys = matched.newCount + matched.recurringCount;
        countedHits = uncountedKeys >= evidenceKeys.length ? addedHits : Math.round((addedHits * uncountedKeys) / evidenceKeys.length);
        const { newHits, recurringHits } = splitHitsByKeys(countedHits, matched.newCount, matched.recurringCount);
        addedNew = newHits;
        addedRecurring = recurringHits;
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Hunt known hits could not be matched for late evidence, its hits count as new', { cause: error, runId: current.internal_id });
      }
    }
    const outcomeChanges = countedHits > 0 && current.hunt_run_mode === HUNT_RUN_MODE_EXECUTE
      && current.hunt_run_status === HUNT_RUN_STATUS_COMPLETED && isHuntRunFinalized(current);
    const automaticVerdict = outcomeChanges && current.verdict_source === HUNT_VERDICT_SOURCE_AUTO;
    const { element: patched } = await patchAttribute(context, HUNT_MANAGER_USER, current.internal_id, ENTITY_TYPE_HUNT_RUN, {
      hits_sample: hitsSample,
      ...huntHitDates(hitsSample, {}, current),
      result_ids: resultIds.slice(0, HUNT_RUN_RESULT_IDS_MAX),
      ...(resultIds.length > HUNT_RUN_RESULT_IDS_MAX ? { results_truncated: true } : {}),
      hits_count: (current.hits_count ?? 0) + countedHits,
      ...(countedHits > 0 || addedNew > 0 || addedRecurring > 0 ? {
        hits_new_count: huntRunNewHits(current) + addedNew,
        hits_recurring_count: (current.hits_recurring_count ?? 0) + addedRecurring,
      } : {}),
      evidence_sample: markMatchedEvidence(mergeEvidence(current.evidence_sample ?? [], sanitizeEvidence(input.evidence_sample)), hitsSample),
      evidence_sources: Array.from(new Set([...(current.evidence_sources ?? []), ...(source ? [source] : [])])).slice(-EVIDENCE_SOURCES_MAX),
      last_evidence_at: lastEvidenceAt.toISOString(),
      // Reopens the finalization of the run, finalizeHuntRun records the automatic verdict again
      ...(automaticVerdict ? { verdict_source: null } : {}),
    });
    const updated = patched as unknown as BasicStoreEntityHuntRun;
    if (automaticVerdict) {
      const finalized = await finalizeHuntRun(context, updated, hunt);
      if ((current.hits_count ?? 0) === 0) {
        scheduleAutomaticTriage(context, finalized, hunt);
      }
      return finalized;
    }
    if (outcomeChanges) {
      await refreshHuntRunOutcome(context, updated, hunt);
    }
    return updated;
  });
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `adds ${results.length} evidence object(s) to a run of hunt \`${hunt.name}\``,
    context_data: { id: hunt.internal_id, entity_type: ENTITY_TYPE_HUNT, input: { run_id: run.internal_id, hits_count: addedHits, source } },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, element, user);
};
// endregion

// region verdict and triage
export const setHuntRunVerdict = async (context: AuthContext, user: AuthUser, runId: string, input: HuntRunVerdictInput) => {
  const run = await findHuntRunById(context, user, runId);
  if (!run) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  const hunt = await loadHuntForRunEdit(context, user, run);
  if (run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW) {
    throw FunctionalError('A translation preview has no verdict', { runId });
  }
  if (run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    throw FunctionalError('Only a completed run can receive a verdict', { runId, status: run.hunt_run_status });
  }
  const requestedSource = (input.source as string | null | undefined) ?? HUNT_VERDICT_SOURCE_ANALYST;
  if (!HUNT_VERDICT_SOURCES.includes(requestedSource) || requestedSource === HUNT_VERDICT_SOURCE_AUTO) {
    throw FunctionalError('A verdict is set by an analyst or an agent', { source: requestedSource });
  }
  const verdict = input.verdict as string;
  // Pending is the state of a run waiting for its verdict, never a verdict: recorded with a source, it would close the
  // finalization of the run and stop the hunt manager from completing it
  if (verdict === HUNT_VERDICT_PENDING) {
    throw FunctionalError('A verdict is true positive, benign or inconclusive', { runId, verdict });
  }
  // Read again under the transition lock: concurrent true positive verdicts open a single Incident draft
  const element = await withHuntRunTransition(context, run.internal_id, async (read) => {
    // A verdict closes the finalization of the run (verdict_source): one still pending is completed first, and a step
    // that keeps failing refuses the verdict, so that the hunt manager keeps retrying it until it closes the run
    const current = isHuntRunFinalized(read) ? read : await completeHuntRunFinalization(context, read);
    if (!isHuntRunFinalized(current)) {
      throw FunctionalError('The run is still being finalized (statistics, incident or coverage), set its verdict again in a few minutes', { runId });
    }
    // The platform decides the provenance, not the client: a verdict is the agent's only when it applies the verdict the
    // agent proposed for this run, any other verdict is the decision of the analyst who sets it
    const appliesProposal = !!current.verdict_proposal && current.verdict_proposal === verdict;
    const source = requestedSource === HUNT_VERDICT_SOURCE_AGENT && appliesProposal ? HUNT_VERDICT_SOURCE_AGENT : HUNT_VERDICT_SOURCE_ANALYST;
    const patch: Record<string, unknown> = {
      verdict,
      verdict_source: source,
      hunt_analyst_feedback: input.hunt_analyst_feedback ? truncate(input.hunt_analyst_feedback, ERROR_MESSAGE_MAX_LENGTH) : current.hunt_analyst_feedback ?? null,
    };
    // The incident is offered with a true positive verdict: the analyst may record the verdict alone. The hits go to the
    // incident still open from a previous run of the hunt on the platform, if any
    const escalates = verdict === HUNT_VERDICT_TRUE_POSITIVE && !current.incident_id && input.create_incident !== false;
    const record = async () => {
      if (escalates) {
        const open = current.draft_id ? null : await findOpenHuntIncident(context, current);
        if (open) {
          await continueHuntIncident(context, hunt, current, open);
          patch.draft_id = open.draftId;
          patch.incident_id = open.incidentId;
          patch.incident_continued = true;
        } else {
          // A draft recorded by an interrupted finalization is reused rather than doubled
          const draftId = current.draft_id ?? await createHuntIncidentWorkspace(context, current);
          patch.draft_id = draftId;
          patch.incident_id = await createHuntIncidentInWorkspace(context, hunt, current, parseIncidentProposal(current.incident_proposal), draftId);
          patch.incident_continued = false;
        }
      }
      const { element: patched } = await patchAttribute(context, user, current.internal_id, ENTITY_TYPE_HUNT_RUN, patch);
      return patched;
    };
    return escalates ? withHuntIncidentLock(current, record) : record();
  });
  addHuntVerdictCount(verdict);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `sets verdict \`${verdict}\` on a run of hunt \`${hunt.name}\``,
    context_data: { id: hunt.internal_id, entity_type: ENTITY_TYPE_HUNT, input },
  });
  return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, element, user);
};

export const triageHuntRun = async (context: AuthContext, user: AuthUser, runId: string) => {
  await checkEnterpriseEdition(context);
  const run = await findHuntRunById(context, user, runId);
  if (!run) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  const hunt = await loadHuntForRunEdit(context, user, run);
  if (run.hunt_run_mode !== HUNT_RUN_MODE_EXECUTE || run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    throw FunctionalError('Only a completed hunt run can be triaged', { runId });
  }
  const triaged = await triageHuntRunWithAgent(context, user, run, hunt, user.id);
  return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, triaged, user);
};
// endregion

// region hunt connectors
export interface HuntConnectorView {
  id: string;
  name: string;
  active: boolean;
  platform: string;
  languages: string[];
  supports_preview: boolean;
  supports_indicators: boolean;
  max_concurrent_runs: number | null;
  security_platform_id: string | null;
  required_permissions: { name: string; purpose: string }[];
  documentation_url: string | null;
  connection_check: NonNullable<BasicStoreEntityConnector['hunt_connection_check']> | null;
  updated_at: string | Date;
}

const REQUIRED_PERMISSIONS_MAX = 20;
const CONNECTION_CHECKS_MAX = 20;

/** The permissions a connector declares, bounded: a name and its purpose each. */
const sanitizeRequiredPermissions = (permissions: { name?: string | null; purpose?: string | null }[] | null | undefined) => {
  return (permissions ?? [])
    .map((permission) => ({ name: truncate(String(permission.name ?? '').trim(), 256), purpose: truncate(String(permission.purpose ?? '').trim(), 1024) }))
    .filter((permission) => permission.name.length > 0)
    .slice(0, REQUIRED_PERMISSIONS_MAX);
};

/** A documentation link shown to the users: an https URL only. */
const sanitizeDocumentationUrl = (url: string | null | undefined) => {
  const trimmed = (url ?? '').trim();
  return /^https:\/\/\S+$/i.test(trimmed) ? truncate(trimmed, 2048) : null;
};

export const toHuntConnectorView = (connector: BasicStoreEntityConnector): HuntConnectorView => ({
  id: connector.internal_id,
  name: connector.name,
  active: connector.active === true,
  // The platform the dispatch reads: a connector registered before its hunt registration is known by its scope
  platform: huntConnectorPlatform(connector) ?? '',
  languages: connector.hunt_languages ?? [],
  supports_preview: connector.hunt_supports_preview !== false,
  supports_indicators: connector.hunt_supports_indicators === true,
  max_concurrent_runs: connector.hunt_max_concurrent_runs ?? null,
  security_platform_id: connector.hunt_security_platform_id ?? null,
  required_permissions: connector.hunt_setup?.required_permissions ?? [],
  documentation_url: connector.hunt_setup?.documentation_url ?? null,
  connection_check: connector.hunt_connection_check ? { ...connector.hunt_connection_check, checks: connector.hunt_connection_check.checks ?? [] } : null,
  updated_at: connector.updated_at,
});

/**
 * The hunt connectors a user sees: those of the internet, and those bound to a security platform the user can read.
 * The dispatch reads every connector (listHuntConnectors), whoever the hunt belongs to.
 */
export const findHuntConnectors = async (context: AuthContext, user: AuthUser, onlyAlive = false) => {
  const connectors = (await listHuntConnectors(context, onlyAlive)).filter((connector) => !!connector.hunt_platform);
  const platformIds = Array.from(new Set(connectors.map((connector) => connector.hunt_security_platform_id).filter((id): id is string => !!id)));
  const readable = platformIds.length > 0
    ? await findByIds<BasicStoreEntitySecurityPlatform>(context, user, platformIds, { type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM })
    : [];
  const readableIds = new Set(readable.map((platform) => platform.internal_id));
  return connectors
    .filter((connector) => !connector.hunt_security_platform_id || readableIds.has(connector.hunt_security_platform_id))
    .map(toHuntConnectorView);
};

const HUNT_CONNECTOR_PLATFORM_LOCK = 'hunt_connector_platform';
export const huntConnectorPlatformLockKey = (securityPlatformId: string) => `${HUNT_CONNECTOR_PLATFORM_LOCK}_${securityPlatformId}`;

export const registerHuntConnector = async (context: AuthContext, user: AuthUser, input: HuntConnectorRegisterInput) => {
  const connector = await storeLoadById<BasicStoreEntityConnector>(context, SYSTEM_USER, input.connector_id, ENTITY_TYPE_CONNECTOR);
  if (!connector) {
    throw ResourceNotFoundError('Connector cannot be found', { connectorId: input.connector_id });
  }
  if (connector.connector_type !== CONNECTOR_INTERNAL_HUNT) {
    throw FunctionalError('Only INTERNAL_HUNT connectors can register a hunt platform', { connectorId: input.connector_id });
  }
  if (!isBypassUser(user) && connector.connector_user_id !== user.id) {
    throw ForbiddenAccess('A hunt connector can only register itself', { connectorId: input.connector_id });
  }
  const platform = input.platform.trim().toLowerCase();
  if (!HUNT_PLATFORMS.includes(platform)) {
    throw FunctionalError(`Hunt platform must be one of ${HUNT_PLATFORMS.join(', ')}`, { platform });
  }
  const languages = Array.from(new Set(input.languages.map((language) => language.trim().toLowerCase()).filter((language) => language.length > 0))).slice(0, MAX_LANGUAGES);
  if (languages.length === 0) {
    throw FunctionalError('A hunt connector must declare at least one query language', { connectorId: input.connector_id });
  }
  const name = input.security_platform_name?.trim();
  let securityPlatformId: string | null = null;
  if (platform !== HUNT_PLATFORM_INTERNET) {
    if (!name) {
      throw FunctionalError('A telemetry hunt connector must declare the security platform it executes against', { connectorId: input.connector_id });
    }
    // Upsert by deterministic identity (name + identity class)
    const securityPlatform = await addSecurityPlatform(context, user, {
      name,
      security_platform_type: input.security_platform_type ?? 'SIEM',
    }) as BasicStoreEntitySecurityPlatform;
    securityPlatformId = securityPlatform.internal_id;
  }
  const maxConcurrent = input.max_concurrent_runs && input.max_concurrent_runs > 0 ? Math.round(input.max_concurrent_runs) : null;
  const bind = async () => {
    // A security platform is one product: connectors of the same kind share it, a connector of another kind never
    // executes its own query language against it
    const otherKind = securityPlatformId ? (await listHuntConnectors(context, false)).find((other) => other.internal_id !== connector.internal_id
      && other.hunt_security_platform_id === securityPlatformId && huntConnectorPlatform(other) !== platform) : undefined;
    if (otherKind) {
      throw FunctionalError(
        `The security platform ${name} is hunted by the ${huntConnectorPlatform(otherKind)} connector ${otherKind.name}: name another security platform, or delete that connector`,
        { connectorId: input.connector_id, securityPlatformId, otherConnectorId: otherKind.internal_id },
      );
    }
    // Bound under the dispatch lock of the connector: a run being published completes first, and a run dispatched after
    // reads the new binding
    return withConnectorDispatchLock(connector.internal_id, () => patchAttribute(context, SYSTEM_USER, connector.internal_id, ENTITY_TYPE_CONNECTOR, {
      hunt_platform: platform,
      hunt_languages: languages,
      hunt_security_platform_id: securityPlatformId,
      hunt_supports_preview: input.supports_preview !== false,
      // Indicator lookups are a capability the connector declares, an older connector does not run indicator hunts
      hunt_supports_indicators: input.supports_indicators === true && platform !== HUNT_PLATFORM_INTERNET,
      hunt_max_concurrent_runs: maxConcurrent,
      hunt_setup: {
        documentation_url: sanitizeDocumentationUrl(input.documentation_url),
        required_permissions: sanitizeRequiredPermissions(input.required_permissions),
      },
    }));
  };
  // Checked and bound under a lock per security platform: two connectors of different kinds registering at once never
  // both bind to it
  const { element } = securityPlatformId ? await withHuntLock(huntConnectorPlatformLockKey(securityPlatformId), bind) : await bind();
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  if ((connector.hunt_security_platform_id ?? null) !== securityPlatformId) {
    await cancelReboundHuntConnectorRuns(context, connector.internal_id, securityPlatformId);
  }
  logApp.info('[OPENCTI-MODULE] Hunt connector registered', { connectorId: connector.internal_id, platform, securityPlatformId });
  return toHuntConnectorView({ ...(element as unknown as BasicStoreEntityConnector), active: true });
};

const loadHuntConnector = async (context: AuthContext, connectorId: string) => {
  const connectors = await listHuntConnectors(context, false);
  const connector = connectors.find((candidate) => candidate.internal_id === connectorId);
  if (!connector) {
    throw ResourceNotFoundError('Hunt connector cannot be found', { connectorId });
  }
  return connector;
};

const HUNT_CONNECTION_CHECK_LOCK = 'hunt_connection_check';
const connectionCheckLockKey = (connectorId: string) => `${HUNT_CONNECTION_CHECK_LOCK}_${connectorId}`;

/**
 * Asks a hunt connector to test its connection and its permissions on its platform. The connector answers with one
 * result per check, in plain words, read on the connector until it arrives. The tests of a connector and its answers run
 * one at a time under its lock, so a test that cannot be sent restores the result it replaced, never a newer test.
 */
export const testHuntConnectorConnection = async (context: AuthContext, user: AuthUser, connectorId: string) => {
  const listed = await loadHuntConnector(context, connectorId);
  if (listed.active !== true) {
    throw FunctionalError('The hunt connector has not answered recently: start it, then test the connection again', { connectorId });
  }
  const { connector, element } = await withHuntLock(connectionCheckLockKey(listed.internal_id), async () => {
    // Read under the lock: the stored result is the one every earlier test left, dispatched or rolled back
    const current = await loadHuntConnector(context, connectorId);
    const check = { id: uuidv4(), status: HUNT_CONNECTION_CHECK_PENDING, requested_at: now(), checked_at: null, checks: [] };
    const work = await createWork(context, user, current, 'Connection test', current.internal_id);
    if (!work) {
      throw FunctionalError('The connection test work cannot be created', { connectorId });
    }
    const previousCheck = current.hunt_connection_check ?? null;
    const patched = await patchAttribute(context, SYSTEM_USER, current.internal_id, ENTITY_TYPE_CONNECTOR, { hunt_connection_check: check });
    try {
      await pushToConnector(current.internal_id, {
        internal: { work_id: work.id, applicant_id: user.id, mode: 'manual', trigger: 'connection_check' },
        event: { event_type: CONNECTOR_INTERNAL_HUNT, mode: HUNT_CONNECTION_CHECK_MODE, connection_check: { id: check.id } },
      });
    } catch (error) {
      // Nothing was published: the work no connector will ever process is deleted and the previous test result comes
      // back, so the connector page does not wait for an answer that cannot arrive
      await deleteWork(context, SYSTEM_USER, work.id)
        .catch((deleteError: unknown) => logApp.warn('[OPENCTI-MODULE] Hunt connection test work cannot be deleted after a failed dispatch', { cause: deleteError, connectorId, workId: work.id }));
      await patchAttribute(context, SYSTEM_USER, current.internal_id, ENTITY_TYPE_CONNECTOR, { hunt_connection_check: previousCheck });
      throw error;
    }
    return { connector: current, element: patched.element };
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'administration',
    message: `tests the connection of the hunt connector \`${connector.name}\``,
    context_data: { id: connector.internal_id, entity_type: ENTITY_TYPE_CONNECTOR, input: {} },
  });
  return toHuntConnectorView({ ...(element as unknown as BasicStoreEntityConnector), active: connector.active });
};

/** The answer of a hunt connector to its last connection test: one result per check, the test passed when all pass. */
export const reportHuntConnectorCheck = async (context: AuthContext, user: AuthUser, input: HuntConnectorCheckReportInput) => {
  const listed = await loadHuntConnector(context, input.connector_id);
  if (!isBypassUser(user) && listed.connector_user_id !== user.id) {
    throw ForbiddenAccess('A hunt connector can only report its own connection test', { connectorId: input.connector_id });
  }
  const checks = input.checks
    .map((item) => ({ name: truncate(item.name.trim(), 256), ok: item.ok === true, message: truncate(item.message.trim(), 2048) }))
    .slice(0, CONNECTION_CHECKS_MAX);
  const passed = checks.length > 0 && checks.every((item) => item.ok);
  // Under the lock of the tests of the connector: the answer never lands on a test being dispatched or rolled back
  const { connector, element, check } = await withHuntLock(connectionCheckLockKey(listed.internal_id), async () => {
    const current = await loadHuntConnector(context, input.connector_id);
    if (current.hunt_connection_check?.id !== input.check_id) {
      throw FunctionalError('This connection test is not the last one requested for the connector', { connectorId: input.connector_id });
    }
    const result = {
      ...current.hunt_connection_check,
      status: passed ? HUNT_CONNECTION_CHECK_PASSED : HUNT_CONNECTION_CHECK_FAILED,
      checked_at: now(),
      checks,
    };
    const patched = await patchAttribute(context, SYSTEM_USER, current.internal_id, ENTITY_TYPE_CONNECTOR, { hunt_connection_check: result });
    return { connector: current, element: patched.element, check: result };
  });
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  logApp.info('[OPENCTI-MODULE] Hunt connector connection tested', { connectorId: connector.internal_id, status: check.status });
  return toHuntConnectorView({ ...(element as unknown as BasicStoreEntityConnector), active: connector.active });
};
// endregion

// region statistics
interface HuntStatisticsArgs {
  huntId?: string | null;
  startDate?: string | Date | null;
  endDate?: string | Date | null;
  interval?: string | null;
}

const HUNT_STATISTICS_DEFAULT_DAYS = 30;
const HUNT_STATISTICS_INTERVALS = ['hour', 'day', 'week', 'month', 'quarter', 'year'];

// Terms aggregations return at most this many buckets (MAX_AGGREGATION_SIZE of the engine)
const TECHNIQUE_VALIDATION_BATCH = 100;

/**
 * Validation of each technique of a hunt by the OpenAEV emulations, counted over every emulation run of the hunt the
 * user can read: four aggregations by technique per batch of techniques, whatever the number of runs.
 */
export const computeHuntTechniqueValidations = async (context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt) => {
  const countByTechnique = async (techniqueIds: string[], extra: { key: string; values: string[]; operator?: FilterOperator }[]) => {
    const buckets = await elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_HUNT_RUN],
      field: 'technique_id',
      normalizeLabel: false,
      noFiltersChecking: true,
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['hunt_id'], values: [hunt.internal_id] },
          { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_EMULATION] },
          { key: ['technique_id'], values: techniqueIds },
          ...extra.map((filter) => ({ key: [filter.key], values: filter.values, operator: filter.operator ?? FilterOperator.Eq })),
        ],
        filterGroups: [],
      },
    });
    return new Map(buckets.map((bucket) => [String(bucket.label), bucket.count]));
  };
  const techniqueIds = hunt[RELATION_HUNT_TECHNIQUES] ?? [];
  const completedFilter = { key: 'hunt_run_status', values: [HUNT_RUN_STATUS_COMPLETED] };
  const validations: { technique_id: string; status: ReturnType<typeof techniqueValidationStatus>; emulation_runs_count: number; detected_runs_count: number }[] = [];
  for (let start = 0; start < techniqueIds.length; start += TECHNIQUE_VALIDATION_BATCH) {
    const batch = techniqueIds.slice(start, start + TECHNIQUE_VALIDATION_BATCH);
    const [runs, detected, active, completed] = await Promise.all([
      countByTechnique(batch, []),
      countByTechnique(batch, [completedFilter, { key: 'hits_count', values: ['0'], operator: FilterOperator.Gt }]),
      countByTechnique(batch, [{ key: 'hunt_run_status', values: HUNT_RUN_ACTIVE_STATUSES }]),
      countByTechnique(batch, [completedFilter]),
    ]);
    batch.forEach((techniqueId) => {
      const counts = {
        runs: runs.get(techniqueId) ?? 0,
        detected: detected.get(techniqueId) ?? 0,
        active: active.get(techniqueId) ?? 0,
        completed: completed.get(techniqueId) ?? 0,
      };
      validations.push({
        technique_id: techniqueId,
        status: techniqueValidationStatus(counts),
        emulation_runs_count: counts.runs,
        detected_runs_count: counts.detected,
      });
    });
  }
  return validations;
};

/**
 * Marks the runs of a hunt as the runs of a deleted hunt, or of a hunt that exists again, in one update: the statistics
 * leave the runs of deleted hunts out with this flag, never by listing every hunt that exists.
 */
export const markHuntRunsOrphaned = async (huntIds: string[], orphaned: boolean) => {
  if (huntIds.length === 0) {
    return;
  }
  await elRawUpdateByQuery({
    index: [READ_INDEX_INTERNAL_OBJECTS],
    refresh: true,
    conflicts: 'proceed',
    body: {
      script: { source: 'ctx._source.hunt_orphaned = params.orphaned;', lang: 'painless', params: { orphaned } },
      query: {
        bool: {
          filter: [
            { term: { 'entity_type.keyword': ENTITY_TYPE_HUNT_RUN } },
            { terms: { 'hunt_id.keyword': huntIds } },
          ],
        },
      },
    },
  });
};

export const computeHuntStatistics = async (context: AuthContext, user: AuthUser, args: HuntStatisticsArgs) => {
  const endDate = args.endDate ? new Date(args.endDate) : new Date();
  const startDate = args.startDate ? new Date(args.startDate) : new Date(endDate.getTime() - HUNT_STATISTICS_DEFAULT_DAYS * 24 * 3600 * 1000);
  const interval = args.interval && HUNT_STATISTICS_INTERVALS.includes(args.interval) ? args.interval : 'day';
  // Runs of a deleted hunt are kept for a hunt restored from the trash, never counted: the figures cover the hunts that
  // exist, through the flag the deletion and the hunt manager keep on the runs. Cancelled runs never ran
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: [
      { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
      ...(args.huntId ? [{ key: ['hunt_id'], values: [args.huntId] }] : []),
      { key: ['hunt_orphaned'], values: ['true'], operator: FilterOperator.NotEq },
      { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_CANCELLED], operator: FilterOperator.NotEq },
    ],
    filterGroups: [],
  };
  // A verdict judges what a run found: only completed runs count in the verdicts, failures count as failed runs
  const completedFilters: FilterGroup = { ...filters, filters: [...filters.filters, { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_COMPLETED] }] };
  const range = { startDate: startDate.toISOString(), endDate: endDate.toISOString() };
  const base = { types: [ENTITY_TYPE_HUNT_RUN], filters, ...range, dateAttribute: 'created_at' };
  // The last run of the period, like every other figure
  const inRangeFilters: FilterGroup = {
    ...filters,
    filters: [
      ...filters.filters,
      { key: ['created_at'], values: [range.startDate], operator: FilterOperator.Gte },
      { key: ['created_at'], values: [range.endDate], operator: FilterOperator.Lte },
    ],
  };
  type Bucket = { label: string; count: number };
  const [verdicts, statuses, platforms, triggers, hitsOverTime, runsOverTime, lastRuns] = await Promise.all([
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, filters: completedFilters, field: 'verdict', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'hunt_run_status', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'security_platform_id', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'hunt_run_trigger', normalizeLabel: false }),
    elHistogramSum(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_HUNT_RUN], filters, ...range, field: 'created_at', interval, sumField: 'hits_count' }),
    elHistogramCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_HUNT_RUN], filters, ...range, field: 'created_at', interval }),
    topEntitiesList<BasicStoreEntityHuntRun>(context, user, [ENTITY_TYPE_HUNT_RUN], { first: 1, orderBy: 'created_at', orderMode: OrderingMode.Desc, filters: inRangeFilters }),
  ]) as [Bucket[], Bucket[], Bucket[], Bucket[], any[], any[], BasicStoreEntityHuntRun[]];
  const countOf = (buckets: Bucket[], label: string) => buckets.find((bucket) => bucket.label === label)?.count ?? 0;
  const platformIds = platforms.map((bucket) => bucket.label).filter((label) => label !== 'unknown');
  const platformEntities = platformIds.length > 0 ? await findByIds<BasicStoreEntity>(context, user, platformIds, { type: ENTITY_TYPE_IDENTITY_SECURITY_PLATFORM }) : [];
  const platformNames = new Map(platformEntities.map((platform) => [platform.internal_id, platform.name]));
  const hitsSeries = fillTimeSeries(startDate, endDate, interval, hitsOverTime);
  const runsSeries = fillTimeSeries(startDate, endDate, interval, runsOverTime);
  return {
    runs_count: statuses.reduce((sum, bucket) => sum + bucket.count, 0),
    completed_runs_count: countOf(statuses, HUNT_RUN_STATUS_COMPLETED),
    failed_runs_count: countOf(statuses, HUNT_RUN_STATUS_FAILED) + countOf(statuses, HUNT_RUN_STATUS_TIMEOUT),
    autonomous_runs_count: triggers.filter((bucket) => HUNT_RUN_AUTONOMOUS_TRIGGERS.includes(bucket.label)).reduce((sum, bucket) => sum + bucket.count, 0),
    hits_total: hitsSeries.reduce((sum: number, point: { value: number }) => sum + point.value, 0),
    true_positive_count: countOf(verdicts, HUNT_VERDICT_TRUE_POSITIVE),
    benign_count: countOf(verdicts, HUNT_VERDICT_BENIGN),
    inconclusive_count: countOf(verdicts, HUNT_VERDICT_INCONCLUSIVE),
    pending_count: countOf(verdicts, HUNT_VERDICT_PENDING),
    last_run_at: lastRuns.length > 0 ? lastRuns[0].created_at : null,
    hits_over_time: hitsSeries,
    runs_over_time: runsSeries,
    // A platform the reader cannot load (deleted or restricted) has an empty label, never its identifier
    runs_per_platform: platforms.map((bucket) => ({
      label: bucket.label === 'unknown' ? HUNT_PLATFORM_INTERNET : String(platformNames.get(bucket.label) ?? ''),
      value: bucket.count,
    })),
    verdict_distribution: verdicts.map((bucket) => ({ label: String(bucket.label), value: bucket.count })),
  };
};
// endregion
