import { findByIds } from '../hunt-loaders';
import type { AuthContext, AuthUser } from '../../../types/user';
import type { BasicStoreEntity, BasicStoreObject } from '../../../types/store';
import type { BasicStoreEntityConnector } from '../../../types/connector';
import { BUS_TOPICS, logApp } from '../../../config/conf';
import { ForbiddenAccess, FunctionalError, LockTimeoutError, ResourceNotFoundError, TYPE_LOCK_ERROR } from '../../../config/errors';
import { lockResources } from '../../../lock/master-lock';
import { createEntity, patchAttribute } from '../../../database/middleware';
import { type EntityOptions, internalLoadById, pageEntitiesConnection, storeLoadById, topEntitiesList } from '../../../database/middleware-loader';
import { elAggregationCount, elCount, elHistogramCount, elHistogramSum } from '../../../database/engine';
import { fillTimeSeries, READ_INDEX_INTERNAL_OBJECTS } from '../../../database/utils';
import { notify } from '../../../database/redis';
import { publishUserAction } from '../../../listener/UserActionListener';
import { ABSTRACT_INTERNAL_OBJECT, CONNECTOR_INTERNAL_HUNT } from '../../../schema/general';
import { ENTITY_TYPE_CONNECTOR } from '../../../schema/internalObject';
import { RELATION_GRANTED_TO, RELATION_OBJECT_MARKING } from '../../../schema/stixRefRelationship';
import {
  FilterMode,
  FilterOperator,
  OrderingMode,
  type FilterGroup,
  type HuntConnectorRegisterInput,
  type HuntRunEvidenceAddInput,
  type HuntRunReportInput,
  type HuntRunVerdictInput,
} from '../../../generated/graphql';
import { HUNT_MANAGER_USER, isBypassUser, SYSTEM_USER } from '../../../utils/access';
import { addFilter } from '../../../utils/filtering/filtering-utils';
import { now } from '../../../utils/format';
import { checkEnterpriseEdition } from '../../../enterprise-edition/ee';
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
  RELATION_HUNT_TARGETS,
  RELATION_HUNT_TECHNIQUES,
} from '../hunt-types';
import { dispatchHuntRun, listHuntConnectors, resolveHuntConnectorTargets } from '../hunt-dispatch';
import { clampInteger, HUNT_CONFIG, HUNT_DEFAULT_TIME_WINDOW_HOURS, sanitizeEvidence, techniqueValidationStatus, truncate } from '../hunt-utils';
import { huntLogicError } from '../hunt-validators';
import { updateHuntRunInformation } from '../hunt-stats';
import { writeHuntCoverageResult } from '../hunt-coverage';
import { createHuntIncidentDraft, parseIncidentProposal } from '../hunt-incident';
import { callHuntAgent, HUNT_TRIAGE_INTENT, validateHuntTriageResult } from '../hunt-agents';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_AUTONOMOUS_TRIGGERS,
  HUNT_RUN_MODE_EXECUTE,
  HUNT_RUN_MODE_PREVIEW,
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
  HUNT_VERDICT_SOURCE_ANALYST,
  HUNT_VERDICT_SOURCE_AUTO,
  HUNT_VERDICT_SOURCES,
  HUNT_VERDICT_TRUE_POSITIVE,
  type HuntPlaybookContext,
} from './huntRun-types';

const ERROR_MESSAGE_MAX_LENGTH = 4000;
const TRANSLATED_QUERY_MAX_LENGTH = 65536;
const RESULT_IDS_MAX = 5000;
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

// The results of a run the user can read, in the order the run recorded them (markings and organizations of every
// object apply). Access is resolved over every recorded id before any pagination, so counts never include the
// objects the user cannot read.
const readableHuntRunResults = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const ids = run.result_ids ?? [];
  if (ids.length === 0) {
    return { elements: [] as BasicStoreObject[], visibleIds: [] as string[] };
  }
  const readable = await findByIds<BasicStoreObject>(context, user, ids);
  const byId = new Map<string, BasicStoreObject>();
  readable.forEach((element) => {
    [element.internal_id, element.standard_id, ...(element.x_opencti_stix_ids ?? [])].forEach((id) => byId.set(id, element));
  });
  const seen = new Set<string>();
  const elements: BasicStoreObject[] = [];
  ids.forEach((id) => {
    const element = byId.get(id);
    if (element && !seen.has(element.internal_id)) {
      seen.add(element.internal_id);
      elements.push(element);
    }
  });
  return { elements, visibleIds: ids.filter((id) => byId.has(id)) };
};

/**
 * Objects produced by a run, as visible to the user, paginated after the cursor of the previous page.
 */
export const findHuntRunResults = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun, first = 50, after?: string | null) => {
  const { elements } = await readableHuntRunResults(context, user, run);
  const start = after ? elements.findIndex((element) => element.internal_id === after) + 1 : 0;
  const page = elements.slice(start, start + Math.min(Math.max(first, 1), 500));
  return {
    edges: page.map((element) => ({ cursor: element.internal_id, node: element })),
    pageInfo: {
      startCursor: page[0]?.internal_id ?? '',
      endCursor: page[page.length - 1]?.internal_id ?? '',
      hasNextPage: start + page.length < elements.length,
      hasPreviousPage: start > 0,
      globalCount: elements.length,
    },
  };
};

// The result ids of a run are only disclosed for the result objects the caller can read, like its results
export const findHuntRunResultIds = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const { visibleIds } = await readableHuntRunResults(context, user, run);
  return visibleIds;
};

const loadHuntForRun = async (context: AuthContext, user: AuthUser, run: BasicStoreEntityHuntRun) => {
  const hunt = await storeLoadById<BasicStoreEntityHunt>(context, user, run.hunt_id, ENTITY_TYPE_HUNT);
  if (!hunt) {
    throw ResourceNotFoundError('Hunt of the run cannot be found', { runId: run.internal_id });
  }
  return hunt;
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
  dispatch?: boolean;
  attempt?: number;
  playbook?: {
    playbookId: string;
    executionId: string;
    stepId: string;
    // Stored on the first run of the group only (continuation of the playbook)
    context?: HuntPlaybookContext;
  } | null;
}

/**
 * Creates one queued run per target connector and dispatches it when the budget allows (the hunt manager
 * dispatches the deferred ones). Runs are created by the hunt manager identity so that they always carry the
 * hunt markings and organizations, the human or system at the origin of the run is kept in triggered_by.
 */
export const createHuntRuns = async (context: AuthContext, hunt: BasicStoreEntityHunt, request: HuntRunRequest): Promise<BasicStoreEntityHuntRun[]> => {
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
  let targets = await resolveHuntConnectorTargets(context, HUNT_MANAGER_USER, hunt, request.securityPlatformIds ?? []);
  if (request.connectorIds && request.connectorIds.length > 0) {
    targets = targets.filter((target) => request.connectorIds?.includes(target.connector.internal_id));
  }
  if (mode === HUNT_RUN_MODE_PREVIEW) {
    targets = targets.filter((target) => target.connector.hunt_supports_preview !== false).slice(0, 1);
  }
  const windowEnd = request.windowEnd ? new Date(request.windowEnd) : new Date();
  const hours = clampInteger(request.timeWindowHours ?? hunt.time_window_hours, 1, HUNT_CONFIG.maxTimeWindowHours, HUNT_DEFAULT_TIME_WINDOW_HOURS);
  const windowStart = request.windowStart ? new Date(request.windowStart) : new Date(windowEnd.getTime() - hours * 3600 * 1000);
  if (windowStart.getTime() >= windowEnd.getTime()) {
    throw FunctionalError('The hunt time window start must be before its end', { windowStart, windowEnd });
  }
  const runs: BasicStoreEntityHuntRun[] = [];
  for (let index = 0; index < targets.length; index += 1) {
    const { connector, securityPlatform } = targets[index];
    const runInput = {
      hunt_id: hunt.internal_id,
      hunt_run_status: HUNT_RUN_STATUS_QUEUED,
      hunt_run_trigger: request.trigger,
      hunt_run_mode: mode,
      security_platform_id: securityPlatform?.internal_id ?? null,
      connector_id: connector.internal_id,
      connector_name: connector.name,
      time_window_start: windowStart.toISOString(),
      time_window_end: windowEnd.toISOString(),
      verdict: HUNT_VERDICT_PENDING,
      attempt: Math.max(1, request.attempt ?? 1),
      aev_inject_id: request.aevInjectId ?? null,
      security_coverage_id: request.securityCoverageId ?? null,
      technique_id: request.techniqueId ?? null,
      triggered_by: request.triggeredBy ?? HUNT_MANAGER_USER.id,
      objectMarking: hunt[RELATION_OBJECT_MARKING] ?? [],
      objectOrganization: hunt[RELATION_GRANTED_TO] ?? [],
      ...(request.playbook ? {
        playbook_id: request.playbook.playbookId,
        playbook_execution_id: request.playbook.executionId,
        playbook_step_id: request.playbook.stepId,
        playbook_leader: index === 0 && !!request.playbook.context,
        playbook_context: index === 0 && request.playbook.context ? JSON.stringify(request.playbook.context) : null,
      } : {}),
    };
    const run = await createEntity(context, HUNT_MANAGER_USER, runInput, ENTITY_TYPE_HUNT_RUN) as BasicStoreEntityHuntRun;
    runs.push(run);
    addHuntRunCount(request.trigger);
    if (request.dispatch !== false) {
      try {
        await dispatchHuntRun(context, run, hunt);
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Hunt run dispatch failed, the hunt manager will retry', { cause: error, runId: run.internal_id });
      }
    }
  }
  if (runs.length > 0 && mode === HUNT_RUN_MODE_EXECUTE) {
    await updateHuntRunInformation(context, hunt.internal_id, { last_run_at: now(), last_run_status: HUNT_RUN_STATUS_QUEUED });
  }
  return runs;
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
  const runs = await createHuntRuns(context, hunt, {
    trigger: 'manual',
    securityPlatformIds: input?.security_platform_ids ?? [],
    timeWindowHours: input?.time_window_hours,
    triggeredBy: user.id,
  });
  if (runs.length === 0) {
    throw FunctionalError('No live hunt connector serves the security platforms of this hunt', { huntId });
  }
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'update',
    event_access: 'extended',
    message: `runs hunt \`${hunt.name}\` on ${runs.length} platform(s)`,
    context_data: { id: hunt.internal_id, entity_type: ENTITY_TYPE_HUNT, input: input ?? {} },
  });
  return runs;
};

export const startHuntPreview = async (context: AuthContext, user: AuthUser, huntId: string, securityPlatformId?: string | null) => {
  const hunt = await storeLoadById<BasicStoreEntityHunt>(context, user, huntId, ENTITY_TYPE_HUNT);
  if (!hunt) {
    throw ResourceNotFoundError('Hunt cannot be found', { huntId });
  }
  const runs = await createHuntRuns(context, hunt, {
    trigger: HUNT_RUN_TRIGGER_PREVIEW,
    mode: HUNT_RUN_MODE_PREVIEW,
    securityPlatformIds: securityPlatformId ? [securityPlatformId] : [],
    triggeredBy: user.id,
  });
  if (runs.length === 0) {
    throw FunctionalError('No live hunt connector supporting translation preview serves this platform', { huntId, securityPlatformId });
  }
  return runs[0];
};

// endregion

// region completion
// Exponential backoff of automatic retries: retry_backoff_minutes, then twice as long at each attempt
export const computeRetryAt = (attempt: number, from = Date.now()) => {
  const backoff = HUNT_CONFIG.retryBackoffMinutes * (2 ** (Math.max(1, attempt) - 1));
  return new Date(from + backoff * 60000).toISOString();
};

const computeAutomaticVerdict = (run: BasicStoreEntityHuntRun): string => {
  if (run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    return HUNT_VERDICT_INCONCLUSIVE;
  }
  return (run.hits_count ?? 0) === 0 ? HUNT_VERDICT_BENIGN : HUNT_VERDICT_PENDING;
};

export const triageHuntRunWithAgent = async (context: AuthContext, run: BasicStoreEntityHuntRun, hunt: BasicStoreEntityHunt, jwtUserId?: string) => {
  const jwtUser = await resolveAgentJwtUser(jwtUserId);
  const history = await topEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
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
    hunt[RELATION_HUNT_TECHNIQUES]?.length ? findByIds<BasicStoreEntity & { x_mitre_id?: string }>(context, HUNT_MANAGER_USER, hunt[RELATION_HUNT_TECHNIQUES] ?? []) : [],
    hunt[RELATION_HUNT_TARGETS]?.length ? findByIds<BasicStoreEntity>(context, HUNT_MANAGER_USER, hunt[RELATION_HUNT_TARGETS] ?? []) : [],
    run.security_platform_id ? internalLoadById<BasicStoreEntity>(context, HUNT_MANAGER_USER, run.security_platform_id) : null,
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
    run: {
      id: run.internal_id,
      hits_count: run.hits_count ?? 0,
      distinct_entities: run.distinct_entities ?? 0,
      time_window: { start: run.time_window_start, end: run.time_window_end },
      security_platform: securityPlatform?.name ?? HUNT_PLATFORM_INTERNET,
      translated_query: run.translated_query ?? '',
      evidence_sample: run.evidence_sample ?? [],
    },
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

/**
 * Post-completion of a run: automatic verdict, Incident draft above the escalation threshold, hunt statistics,
 * Security Coverage write-back for emulation runs and agent triage (Enterprise Edition, never applied as verdict).
 */
const finalizeHuntRun = async (context: AuthContext, run: BasicStoreEntityHuntRun, hunt: BasicStoreEntityHunt) => {
  if (run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW) {
    return run;
  }
  const verdict = computeAutomaticVerdict(run);
  const patch: Record<string, unknown> = { verdict, verdict_source: HUNT_VERDICT_SOURCE_AUTO };
  if (run.hunt_run_status === HUNT_RUN_STATUS_COMPLETED && (run.hits_count ?? 0) >= hunt.escalation_threshold && !run.incident_id) {
    try {
      const { draftId, incidentId } = await createHuntIncidentDraft(context, hunt, run, null);
      patch.incident_id = incidentId;
      patch.draft_id = draftId;
    } catch (error) {
      logApp.error('[OPENCTI-MODULE] Hunt incident draft creation failed', { cause: error, runId: run.internal_id });
    }
  }
  const { element } = await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, patch);
  const current = element as unknown as BasicStoreEntityHuntRun;
  await updateHuntRunInformation(context, hunt.internal_id, {
    last_run_at: current.completed_at ?? now(),
    last_run_status: current.hunt_run_status,
    last_hits_count: current.hits_count ?? 0,
  });
  if (current.hunt_run_status === HUNT_RUN_STATUS_COMPLETED) {
    try {
      await writeHuntCoverageResult(context, current);
    } catch (error) {
      logApp.error('[OPENCTI-MODULE] Hunt coverage write-back failed', { cause: error, runId: current.internal_id });
    }
  }
  return current;
};

const isTriageAvailable = async (context: AuthContext) => {
  try {
    await checkEnterpriseEdition(context);
    return true;
  } catch {
    return false;
  }
};

// Automatic triage of runs with hits never blocks the connector report
const scheduleAutomaticTriage = (context: AuthContext, run: BasicStoreEntityHuntRun, hunt: BasicStoreEntityHunt) => {
  if (run.hunt_run_mode !== HUNT_RUN_MODE_EXECUTE || run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED || (run.hits_count ?? 0) === 0) {
    return;
  }
  isTriageAvailable(context)
    .then((available) => (available ? triageHuntRunWithAgent(context, run, hunt) : null))
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
  const lockKey = `${HUNT_RUN_TRANSITION_LOCK}_${runId}`;
  let lock;
  try {
    lock = await lockResources([lockKey]);
    const current = await findHuntRunById(context, HUNT_MANAGER_USER, runId);
    if (!current) {
      throw ResourceNotFoundError('Hunt run cannot be found', { runId });
    }
    return await transition(current);
  } catch (e: any) {
    if (e.name === TYPE_LOCK_ERROR) {
      throw LockTimeoutError({ participantIds: [lockKey] });
    }
    throw e;
  } finally {
    if (lock) {
      await lock.unlock();
    }
  }
};

/**
 * Consumes the automatic retry planned on a terminated run, under its transition lock, so that the hunt manager and a
 * manual retry never both replace the run. Returns the run as read under the lock and whether a retry was planned.
 */
export const consumeScheduledRetry = async (context: AuthContext, runId: string) => {
  return withHuntRunTransition(context, runId, async (run) => {
    const planned = !!run.next_retry_at;
    if (planned) {
      await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: null });
    }
    return { run, planned };
  });
};

/**
 * Manual retry of a terminated run: the next attempt on the same connector and window. It replaces the automatic retry
 * planned on the run, if any, which is restored when the replacement cannot be created.
 */
export const retryHuntRun = async (context: AuthContext, user: AuthUser, runId: string) => {
  const reachable = await findHuntRunById(context, user, runId);
  if (!reachable) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  if (!HUNT_RUN_TERMINAL_STATUSES.includes(reachable.hunt_run_status)) {
    throw FunctionalError('Only a terminated run can be retried', { runId, status: reachable.hunt_run_status });
  }
  const hunt = await loadHuntForRun(context, user, reachable);
  const { run, planned } = await consumeScheduledRetry(context, reachable.internal_id);
  try {
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
      triggeredBy: user.id,
      attempt: (run.attempt ?? 1) + 1,
      playbook: planned && run.playbook_id && run.playbook_execution_id && run.playbook_step_id
        ? { playbookId: run.playbook_id, executionId: run.playbook_execution_id, stepId: run.playbook_step_id }
        : null,
    });
    if (runs.length === 0) {
      throw FunctionalError('The hunt connector of this run is not alive anymore', { runId, connectorId: run.connector_id });
    }
    return runs[0];
  } catch (error) {
    if (planned) {
      await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: run.next_retry_at });
    }
    throw error;
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
  const connectors = await listHuntConnectors(context, false);
  const connector = connectors.find((c) => c.internal_id === reported.connector_id);
  if (!isBypassUser(user) && connector?.connector_user_id !== user.id) {
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
    throw FunctionalError('The hunt run is already terminated', { runId: run.internal_id, status: run.hunt_run_status });
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
      patch.hits_count = Math.max(0, Math.round(input.hits_count ?? 0));
      patch.distinct_entities = Math.max(0, Math.round(input.distinct_entities ?? 0));
      patch.evidence_sample = sanitizeEvidence(input.evidence_sample);
      patch.result_ids = Array.from(new Set((input.result_ids ?? []).filter((id) => typeof id === 'string' && id.length > 0))).slice(0, RESULT_IDS_MAX);
    }
    if (typeof input.cost_ms === 'number') {
      patch.cost_ms = Math.max(0, Math.round(input.cost_ms));
    }
  }
  // A timeout is a run the connector stopped at its deadline: same completion path as a failure
  if (status === HUNT_RUN_STATUS_FAILED || status === HUNT_RUN_STATUS_TIMEOUT) {
    patch.completed_at = reportedAt;
    patch.error_message = truncate(input.error ?? (status === HUNT_RUN_STATUS_TIMEOUT ? 'The run exceeded its deadline' : 'Unknown error'), ERROR_MESSAGE_MAX_LENGTH);
    // Automatic retries with exponential backoff, translation previews are never retried
    if (run.hunt_run_mode === HUNT_RUN_MODE_EXECUTE && run.attempt <= HUNT_CONFIG.maxRetries) {
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
  const patch: Record<string, unknown> = {
    hunt_run_status: HUNT_RUN_STATUS_TIMEOUT,
    completed_at: now(),
    error_message: truncate(reason, ERROR_MESSAGE_MAX_LENGTH),
  };
  // A run that never reached its connector is not retried: its connector is gone or saturated
  if (run.dispatched_at && run.hunt_run_mode === HUNT_RUN_MODE_EXECUTE && run.attempt <= HUNT_CONFIG.maxRetries) {
    patch.next_retry_at = computeRetryAt(run.attempt);
  }
  const { element } = await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, patch);
  let updated = element as unknown as BasicStoreEntityHuntRun;
  const hunt = await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT });
  if (hunt) {
    updated = await finalizeHuntRun(context, updated, hunt);
  }
  return notify(BUS_TOPICS[ENTITY_TYPE_HUNT_RUN].EDIT_TOPIC, updated, HUNT_MANAGER_USER);
};
// endregion

// region late evidence
const EVIDENCE_IDS_PER_CALL = 1000;
const EVIDENCE_SOURCE_MAX_LENGTH = 128;
const EVIDENCE_SOURCES_MAX = 20;

/**
 * Evidence found outside the dispatch of a run (a SIEM alert action, a follow-up search, a late result), on any run
 * status: result objects are merged, hits are added, the evidence sample is merged under the platform caps. The status
 * and the verdict are never changed, an analyst or an agent reviews the run.
 */
export const addHuntRunEvidence = async (context: AuthContext, user: AuthUser, runId: string, input: HuntRunEvidenceAddInput) => {
  const run = await findHuntRunById(context, user, runId);
  if (!run) {
    throw ResourceNotFoundError('Hunt run cannot be found', { runId });
  }
  const hunt = await loadHuntForRun(context, user, run);
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
    const { element: patched } = await patchAttribute(context, HUNT_MANAGER_USER, current.internal_id, ENTITY_TYPE_HUNT_RUN, {
      result_ids: Array.from(new Set([...(current.result_ids ?? []), ...results.map((result) => result.standard_id)])).slice(0, RESULT_IDS_MAX),
      hits_count: (current.hits_count ?? 0) + addedHits,
      evidence_sample: sanitizeEvidence([...(current.evidence_sample ?? []), ...(input.evidence_sample ?? [])]),
      evidence_sources: Array.from(new Set([...(current.evidence_sources ?? []), ...(source ? [source] : [])])).slice(-EVIDENCE_SOURCES_MAX),
      last_evidence_at: lastEvidenceAt.toISOString(),
    });
    return patched;
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
  const hunt = await loadHuntForRun(context, user, run);
  if (run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW) {
    throw FunctionalError('A translation preview has no verdict', { runId });
  }
  if (run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    throw FunctionalError('Only a completed run can receive a verdict', { runId, status: run.hunt_run_status });
  }
  const source = (input.source as string | null | undefined) ?? HUNT_VERDICT_SOURCE_ANALYST;
  if (!HUNT_VERDICT_SOURCES.includes(source) || source === HUNT_VERDICT_SOURCE_AUTO) {
    throw FunctionalError('A verdict is set by an analyst or an agent', { source });
  }
  const verdict = input.verdict as string;
  // Read again under the transition lock: concurrent true positive verdicts open a single Incident draft
  const element = await withHuntRunTransition(context, run.internal_id, async (current) => {
    const patch: Record<string, unknown> = {
      verdict,
      verdict_source: source,
      analyst_feedback: input.analyst_feedback ? truncate(input.analyst_feedback, ERROR_MESSAGE_MAX_LENGTH) : current.analyst_feedback ?? null,
    };
    if (verdict === HUNT_VERDICT_TRUE_POSITIVE && !current.incident_id) {
      const { draftId, incidentId } = await createHuntIncidentDraft(context, hunt, current, parseIncidentProposal(current.incident_proposal));
      patch.incident_id = incidentId;
      patch.draft_id = draftId;
    }
    const { element: patched } = await patchAttribute(context, user, current.internal_id, ENTITY_TYPE_HUNT_RUN, patch);
    return patched;
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
  const hunt = await loadHuntForRun(context, user, run);
  if (run.hunt_run_mode !== HUNT_RUN_MODE_EXECUTE || run.hunt_run_status !== HUNT_RUN_STATUS_COMPLETED) {
    throw FunctionalError('Only a completed hunt run can be triaged', { runId });
  }
  const triaged = await triageHuntRunWithAgent(context, run, hunt, user.id);
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
  max_concurrent_runs: number | null;
  security_platform_id: string | null;
  updated_at: string | Date;
}

const toHuntConnectorView = (connector: BasicStoreEntityConnector): HuntConnectorView => ({
  id: connector.internal_id,
  name: connector.name,
  active: connector.active === true,
  platform: connector.hunt_platform ?? '',
  languages: connector.hunt_languages ?? [],
  supports_preview: connector.hunt_supports_preview !== false,
  max_concurrent_runs: connector.hunt_max_concurrent_runs ?? null,
  security_platform_id: connector.hunt_security_platform_id ?? null,
  updated_at: connector.updated_at,
});

export const findHuntConnectors = async (context: AuthContext, onlyAlive = false) => {
  const connectors = await listHuntConnectors(context, onlyAlive);
  return connectors.filter((connector) => !!connector.hunt_platform).map(toHuntConnectorView);
};

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
  let securityPlatformId: string | null = null;
  if (platform !== HUNT_PLATFORM_INTERNET) {
    const name = input.security_platform_name?.trim();
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
  const { element } = await patchAttribute(context, SYSTEM_USER, connector.internal_id, ENTITY_TYPE_CONNECTOR, {
    hunt_platform: platform,
    hunt_languages: languages,
    hunt_security_platform_id: securityPlatformId,
    hunt_supports_preview: input.supports_preview !== false,
    hunt_max_concurrent_runs: maxConcurrent,
  });
  // Notify configuration change for caching system
  await notify(BUS_TOPICS[ABSTRACT_INTERNAL_OBJECT].EDIT_TOPIC, element, user);
  logApp.info('[OPENCTI-MODULE] Hunt connector registered', { connectorId: connector.internal_id, platform, securityPlatformId });
  return toHuntConnectorView({ ...(element as unknown as BasicStoreEntityConnector), active: true });
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

/**
 * Validation of each technique of a hunt by the OpenAEV emulations, counted over every emulation run of the hunt the
 * user can read.
 */
export const computeHuntTechniqueValidations = async (context: AuthContext, user: AuthUser, hunt: BasicStoreEntityHunt) => {
  const countEmulationRuns = (techniqueId: string, extra: { key: string; values: string[]; operator?: FilterOperator }[]) => {
    return elCount(context, user, READ_INDEX_INTERNAL_OBJECTS, {
      types: [ENTITY_TYPE_HUNT_RUN],
      noFiltersChecking: true,
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['hunt_id'], values: [hunt.internal_id] },
          { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_EMULATION] },
          { key: ['technique_id'], values: [techniqueId] },
          ...extra.map((filter) => ({ key: [filter.key], values: filter.values, operator: filter.operator ?? FilterOperator.Eq })),
        ],
        filterGroups: [],
      },
    });
  };
  const techniqueIds = hunt[RELATION_HUNT_TECHNIQUES] ?? [];
  const validations = [];
  for (let index = 0; index < techniqueIds.length; index += 1) {
    const techniqueId = techniqueIds[index];
    const completedFilter = { key: 'hunt_run_status', values: [HUNT_RUN_STATUS_COMPLETED] };
    const [runs, detected, active, completed] = await Promise.all([
      countEmulationRuns(techniqueId, []),
      countEmulationRuns(techniqueId, [completedFilter, { key: 'hits_count', values: ['0'], operator: FilterOperator.Gt }]),
      countEmulationRuns(techniqueId, [{ key: 'hunt_run_status', values: HUNT_RUN_ACTIVE_STATUSES }]),
      countEmulationRuns(techniqueId, [completedFilter]),
    ]);
    validations.push({
      technique_id: techniqueId,
      status: techniqueValidationStatus({ runs, detected, active, completed }),
      emulation_runs_count: runs,
      detected_runs_count: detected,
    });
  }
  return validations;
};

export const computeHuntStatistics = async (context: AuthContext, user: AuthUser, args: HuntStatisticsArgs) => {
  const endDate = args.endDate ? new Date(args.endDate) : new Date();
  const startDate = args.startDate ? new Date(args.startDate) : new Date(endDate.getTime() - HUNT_STATISTICS_DEFAULT_DAYS * 24 * 3600 * 1000);
  const interval = args.interval && HUNT_STATISTICS_INTERVALS.includes(args.interval) ? args.interval : 'day';
  const executeFilter = { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] };
  const filters: FilterGroup = {
    mode: FilterMode.And,
    filters: args.huntId ? [executeFilter, { key: ['hunt_id'], values: [args.huntId] }] : [executeFilter],
    filterGroups: [],
  };
  const range = { startDate: startDate.toISOString(), endDate: endDate.toISOString() };
  const base = { types: [ENTITY_TYPE_HUNT_RUN], filters, ...range, dateAttribute: 'created_at' };
  const [verdicts, statuses, platforms, triggers, hitsOverTime, runsOverTime, lastRuns] = await Promise.all([
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'verdict', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'hunt_run_status', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'security_platform_id', normalizeLabel: false }),
    elAggregationCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { ...base, field: 'hunt_run_trigger', normalizeLabel: false }),
    elHistogramSum(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_HUNT_RUN], filters, ...range, field: 'created_at', interval, sumField: 'hits_count' }),
    elHistogramCount(context, user, READ_INDEX_INTERNAL_OBJECTS, { types: [ENTITY_TYPE_HUNT_RUN], filters, ...range, field: 'created_at', interval }),
    topEntitiesList<BasicStoreEntityHuntRun>(context, user, [ENTITY_TYPE_HUNT_RUN], { first: 1, orderBy: 'created_at', orderMode: OrderingMode.Desc, filters }),
  ]);
  const countOf = (buckets: { label: string; count: number }[], label: string) => buckets.find((bucket) => bucket.label === label)?.count ?? 0;
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
    runs_per_platform: platforms.map((bucket) => ({
      label: bucket.label === 'unknown' ? HUNT_PLATFORM_INTERNET : String(platformNames.get(bucket.label) ?? bucket.label),
      value: bucket.count,
    })),
    verdict_distribution: verdicts.map((bucket) => ({ label: String(bucket.label), value: bucket.count })),
  };
};
// endregion
