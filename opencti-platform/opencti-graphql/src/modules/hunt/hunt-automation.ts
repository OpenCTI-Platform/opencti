import type { Operation } from 'fast-json-patch';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity, BasicStoreRelation } from '../../types/store';
import type { DataEvent, SseEvent, UpdateEvent } from '../../types/event';
import { logApp } from '../../config/conf';
import { deleteElementById, patchAttribute } from '../../database/middleware';
import { fullRelationsList, internalLoadById, topEntitiesList } from '../../database/middleware-loader';
import { elCount } from '../../database/engine';
import { EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { fetchStreamEventsRangeFromEventId } from '../../database/stream/stream-handler';
import { type FilterGroup, FilterMode, FilterOperator, OrderingMode } from '../../generated/graphql';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { HUNT_MANAGER_USER } from '../../utils/access';
import { doYield } from '../../utils/eventloop-utils';
import { now } from '../../utils/format';
import { findByIds } from './hunt-loaders';
import {
  type BasicStoreEntityHunt,
  ENTITY_TYPE_HUNT,
  HUNT_SCHEDULE_MANUAL,
  HUNT_SCHEDULE_STANDING,
  HUNT_STATUS_ACTIVE,
  HUNT_STATUS_DRAFT,
  HUNT_STATUS_RETIRED,
  RELATION_HUNT_SOURCES,
  RELATION_HUNT_TARGETS,
  RELATION_HUNT_TECHNIQUES,
} from './hunt-types';
import {
  type BasicStoreEntityHuntRun,
  ENTITY_TYPE_HUNT_RUN,
  HUNT_RUN_ACTIVE_STATUSES,
  HUNT_RUN_MODE_EXECUTE,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_FAILED,
  HUNT_RUN_STATUS_QUEUED,
  HUNT_RUN_STATUS_TIMEOUT,
  HUNT_RUN_TRIGGER_RETRY,
  HUNT_RUN_TRIGGER_SCHEDULE,
  HUNT_RUN_TRIGGER_STANDING,
  type HuntPlaybookContext,
} from './huntRun/huntRun-types';
import { computeRetryAt, createHuntRuns, expireHuntRun } from './huntRun/huntRun-domain';
import { dispatchHuntRun, listHuntConnectors } from './hunt-dispatch';
import { computeNextRunAt } from './hunt-schedule';
import { updateHuntRunInformation } from './hunt-stats';
import { HUNT_CONFIG, parseHuntFilterGroup } from './hunt-utils';
import { findPlaybookHuntRuns, isHuntRunGroupSettled, resumeHuntPlaybookStep } from './hunt-playbook';

export const HUNT_MANAGER_STREAM_STATE = 'hunt_manager';
// Upper bound of the hunts evaluated by one tick of a phase (schedules, PIR arming, standing hunts)
export const HUNT_AUTOMATION_MAX_HUNTS = 500;
// Soft coupling with Threat Pulse: entities whose community trend rises make their standing hunts react faster
export const PULSE_TREND_ATTRIBUTE = 'pulse_trend';
const PULSE_TREND_RISING = 'rising';
// Stream refs that, when added, mean that the knowledge around a hunt moved (a report adds a TTP, a sighting of a threat ...)
const STANDING_REF_FIELDS = ['object_refs', 'source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
const STANDING_MAX_REFS_PER_EVENT = 2000;

const minutesAgo = (minutes: number) => new Date(Date.now() - minutes * 60000).toISOString();

const andFilters = (filters: FilterGroup['filters'], filterGroups: FilterGroup[] = []): FilterGroup => ({ mode: FilterMode.And, filters, filterGroups });

const listRuns = (context: AuthContext, filters: FilterGroup['filters'], orderBy = 'created_at', first = HUNT_CONFIG.maxRunsPerTick) => {
  return topEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    first,
    orderBy,
    orderMode: OrderingMode.Asc,
    filters: andFilters(filters),
    noFiltersChecking: true,
  });
};

const listHunts = (context: AuthContext, filters: FilterGroup['filters'], filterGroups: FilterGroup[] = [], orderBy = 'created_at') => {
  return topEntitiesList<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT], {
    first: HUNT_AUTOMATION_MAX_HUNTS,
    orderBy,
    orderMode: OrderingMode.Asc,
    filters: andFilters(filters, filterGroups),
    noFiltersChecking: true,
  });
};

const startAutomaticRuns = async (context: AuthContext, hunt: BasicStoreEntityHunt, trigger: string) => {
  try {
    const runs = await createHuntRuns(context, hunt, { trigger });
    if (runs.length === 0) {
      logApp.info('[OPENCTI-MODULE] Hunt not run, no live hunt connector serves its scope', { huntId: hunt.internal_id, trigger });
    }
    return runs.length;
  } catch (error) {
    logApp.error('[OPENCTI-MODULE] Hunt automatic run failed to start', { cause: error, huntId: hunt.internal_id, trigger });
    return 0;
  }
};

// region run lifecycle (Community Edition: manual runs rely on it too)
/**
 * Runs the platform stops waiting for: dispatched and not reported within the run timeout (the preview timeout for
 * translation previews), or never accepted by a live connector within the queue expiry.
 */
export const expireStaleHuntRuns = async (context: AuthContext): Promise<number> => {
  const active = { key: ['hunt_run_status'], values: HUNT_RUN_ACTIVE_STATUSES };
  const queued = { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_QUEUED] };
  const execute = { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] };
  const preview = { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_PREVIEW] };
  const notDispatched = { key: ['dispatched_at'], values: [], operator: FilterOperator.Nil };
  const dispatchedBefore = (minutes: number) => ({ key: ['dispatched_at'], values: [minutesAgo(minutes)], operator: FilterOperator.Lte });
  const createdBefore = (minutes: number) => ({ key: ['created_at'], values: [minutesAgo(minutes)], operator: FilterOperator.Lte });
  const phases = [
    {
      filters: [active, execute, dispatchedBefore(HUNT_CONFIG.runTimeoutMinutes)],
      reason: `The hunt connector did not complete the run within ${HUNT_CONFIG.runTimeoutMinutes} minutes`,
    },
    {
      filters: [active, preview, dispatchedBefore(HUNT_CONFIG.previewTimeoutMinutes)],
      reason: `The hunt connector did not translate the query within ${HUNT_CONFIG.previewTimeoutMinutes} minutes`,
    },
    {
      filters: [queued, execute, notDispatched, createdBefore(HUNT_CONFIG.queueExpiryHours * 60)],
      reason: `No live hunt connector accepted the run within ${HUNT_CONFIG.queueExpiryHours} hours`,
    },
    {
      filters: [queued, preview, notDispatched, createdBefore(HUNT_CONFIG.previewTimeoutMinutes)],
      reason: `No live hunt connector accepted the translation preview within ${HUNT_CONFIG.previewTimeoutMinutes} minutes`,
    },
  ];
  let expired = 0;
  for (let phaseIndex = 0; phaseIndex < phases.length; phaseIndex += 1) {
    const { filters, reason } = phases[phaseIndex];
    const runs = await listRuns(context, filters);
    for (let index = 0; index < runs.length; index += 1) {
      try {
        await expireHuntRun(context, runs[index], reason);
        expired += 1;
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Hunt run expiration failed', { cause: error, runId: runs[index].internal_id });
      }
    }
  }
  return expired;
};

/**
 * Automatic retries of failed or timed out runs once their backoff elapsed: a new run on the same connector and window,
 * with the next attempt number. Runs of draft or retired hunts are given up, as well as runs whose connector stays down
 * beyond the queue expiry.
 */
export const retryFailedHuntRuns = async (context: AuthContext): Promise<number> => {
  const runs = await listRuns(context, [
    { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT] },
    { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
    { key: ['next_retry_at'], values: [now()], operator: FilterOperator.Lte },
  ], 'next_retry_at');
  let retried = 0;
  for (let index = 0; index < runs.length; index += 1) {
    const run = runs[index];
    const hunt = await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT });
    const expiredSince = run.completed_at ? Date.now() - new Date(run.completed_at).getTime() : 0;
    const giveUp = !hunt || [HUNT_STATUS_DRAFT, HUNT_STATUS_RETIRED].includes(hunt.hunt_status) || expiredSince > HUNT_CONFIG.queueExpiryHours * 3600000;
    // The retry schedule is consumed first: a crash between the two steps never retries a run twice
    await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: null });
    if (!giveUp && hunt) {
      try {
        const created = await createHuntRuns(context, hunt, {
          trigger: HUNT_RUN_TRIGGER_RETRY,
          mode: run.hunt_run_mode,
          securityPlatformIds: run.security_platform_id ? [run.security_platform_id] : [],
          connectorIds: run.connector_id ? [run.connector_id] : [],
          windowStart: run.time_window_start,
          windowEnd: run.time_window_end,
          aevInjectId: run.aev_inject_id,
          securityCoverageId: run.security_coverage_id,
          techniqueId: run.technique_id,
          triggeredBy: run.triggered_by,
          attempt: (run.attempt ?? 1) + 1,
          playbook: run.playbook_id && run.playbook_execution_id && run.playbook_step_id
            ? { playbookId: run.playbook_id, executionId: run.playbook_execution_id, stepId: run.playbook_step_id }
            : null,
        });
        if (created.length > 0) {
          retried += 1;
        } else {
          // Connector down: try again later, the queue expiry bounds the wait
          await patchAttribute(context, HUNT_MANAGER_USER, run.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: computeRetryAt(run.attempt ?? 1) });
        }
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Hunt run retry failed', { cause: error, runId: run.internal_id });
      }
    }
  }
  return retried;
};

/**
 * Queued runs deferred by the connector budgets or a connector outage, translation previews first (an analyst waits
 * for them), then the oldest runs.
 */
export const dispatchQueuedHuntRuns = async (context: AuthContext): Promise<number> => {
  const runs = await listRuns(context, [
    { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_QUEUED] },
    { key: ['dispatched_at'], values: [], operator: FilterOperator.Nil },
  ]);
  const ordered = [...runs.filter((run) => run.hunt_run_mode === HUNT_RUN_MODE_PREVIEW), ...runs.filter((run) => run.hunt_run_mode !== HUNT_RUN_MODE_PREVIEW)];
  const hunts = new Map<string, BasicStoreEntityHunt | undefined>();
  let dispatched = 0;
  for (let index = 0; index < ordered.length; index += 1) {
    const run = ordered[index];
    if (!hunts.has(run.hunt_id)) {
      hunts.set(run.hunt_id, await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT }) ?? undefined);
    }
    const hunt = hunts.get(run.hunt_id);
    try {
      if (!hunt) {
        await expireHuntRun(context, run, 'The hunt of the run does not exist anymore');
      } else if (await dispatchHuntRun(context, run, hunt)) {
        dispatched += 1;
      }
    } catch (error) {
      logApp.error('[OPENCTI-MODULE] Hunt run dispatch failed', { cause: error, runId: run.internal_id });
    }
  }
  return dispatched;
};

/**
 * Run retention: translation previews and executed runs older than their retention are deleted. Runs of a deleted hunt
 * are kept until then, so that a hunt restored from the trash keeps its history.
 */
export const purgeExpiredHuntRuns = async (context: AuthContext): Promise<number> => {
  const phases = [
    { mode: HUNT_RUN_MODE_PREVIEW, days: HUNT_CONFIG.previewRetentionDays },
    { mode: HUNT_RUN_MODE_EXECUTE, days: HUNT_CONFIG.runRetentionDays },
  ];
  let purged = 0;
  for (let phaseIndex = 0; phaseIndex < phases.length; phaseIndex += 1) {
    const { mode, days } = phases[phaseIndex];
    const runs = await listRuns(context, [
      { key: ['hunt_run_mode'], values: [mode] },
      { key: ['hunt_run_status'], values: HUNT_RUN_ACTIVE_STATUSES, operator: FilterOperator.NotEq, mode: FilterMode.And },
      { key: ['created_at'], values: [minutesAgo(days * 24 * 60)], operator: FilterOperator.Lte },
    ]);
    for (let index = 0; index < runs.length; index += 1) {
      try {
        await deleteElementById(context, HUNT_MANAGER_USER, runs[index].internal_id, ENTITY_TYPE_HUNT_RUN);
        purged += 1;
      } catch (error) {
        logApp.error('[OPENCTI-MODULE] Hunt run purge failed', { cause: error, runId: runs[index].internal_id });
      }
    }
  }
  return purged;
};

/**
 * Continuation of the playbooks waiting on hunt steps: once every run of a step is settled, the step resumes.
 * The resume is recorded first so that a step never resumes twice (at most once delivery of the playbook).
 */
export const resumeSettledHuntPlaybooks = async (context: AuthContext): Promise<number> => {
  const leaders = await listRuns(context, [
    { key: ['playbook_leader'], values: ['true'] },
    { key: ['playbook_resumed_at'], values: [], operator: FilterOperator.Nil },
  ]);
  let resumed = 0;
  for (let index = 0; index < leaders.length; index += 1) {
    const leader = leaders[index];
    try {
      const group = leader.playbook_execution_id ? await findPlaybookHuntRuns(context, leader.playbook_execution_id, leader.playbook_step_id) : [leader];
      if (isHuntRunGroupSettled(group) && leader.playbook_context) {
        await patchAttribute(context, HUNT_MANAGER_USER, leader.internal_id, ENTITY_TYPE_HUNT_RUN, { playbook_resumed_at: now() });
        await resumeHuntPlaybookStep(context, JSON.parse(leader.playbook_context) as HuntPlaybookContext, group);
        resumed += 1;
      }
    } catch (error) {
      logApp.error('[OPENCTI-MODULE] Hunt playbook resume failed', { cause: error, runId: leader.internal_id, playbookId: leader.playbook_id });
    }
  }
  return resumed;
};
// endregion

// region autonomous hunts (Enterprise Edition)
const isWaitingForPir = (hunt: BasicStoreEntityHunt) => hunt.hunt_pir_activation === true && hunt.hunt_pir_armed !== true;

/**
 * Cron hunts: due hunts run (unless their PIR activation is not armed) and their next occurrence is computed from now,
 * so that an outage never replays the missed occurrences. Hunts approved from a draft get their first occurrence here.
 */
export const runScheduledHunts = async (context: AuthContext): Promise<number> => {
  const hunts = await listHunts(context, [
    { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
    { key: ['hunt_schedule'], values: [HUNT_SCHEDULE_MANUAL, HUNT_SCHEDULE_STANDING], operator: FilterOperator.NotEq, mode: FilterMode.And },
  ], [{
    mode: FilterMode.Or,
    filters: [
      { key: ['next_run_at'], values: [now()], operator: FilterOperator.Lte },
      { key: ['next_run_at'], values: [], operator: FilterOperator.Nil },
    ],
    filterGroups: [],
  }], 'next_run_at');
  let started = 0;
  for (let index = 0; index < hunts.length; index += 1) {
    const hunt = hunts[index];
    if (hunt.next_run_at && started < HUNT_CONFIG.maxRunsPerTick && !isWaitingForPir(hunt)) {
      started += await startAutomaticRuns(context, hunt, HUNT_RUN_TRIGGER_SCHEDULE);
    }
    const nextRunAt = computeNextRunAt(hunt.hunt_schedule, new Date());
    await updateHuntRunInformation(context, hunt.internal_id, { next_run_at: nextRunAt ? nextRunAt.toISOString() : null });
  }
  return started;
};

/**
 * PIR activation: a hunt with PIR activation is armed while one of its targets is flagged by a PIR. Arming runs the hunt
 * once; while armed its schedule and standing triggers apply, disarmed it waits. The hunt status stays the analyst's.
 */
export const reconcilePirActivatedHunts = async (context: AuthContext): Promise<number> => {
  const hunts = await listHunts(context, [
    { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
    { key: ['hunt_pir_activation'], values: ['true'] },
  ]);
  if (hunts.length === 0) {
    return 0;
  }
  const targetIds = Array.from(new Set(hunts.flatMap((hunt) => hunt[RELATION_HUNT_TARGETS] ?? [])));
  const inPirRelations = targetIds.length > 0
    ? await fullRelationsList<BasicStoreRelation>(context, HUNT_MANAGER_USER, RELATION_IN_PIR, { fromId: targetIds })
    : [];
  const flagged = new Set(inPirRelations.map((relation) => relation.fromId));
  let started = 0;
  for (let index = 0; index < hunts.length; index += 1) {
    const hunt = hunts[index];
    const armed = (hunt[RELATION_HUNT_TARGETS] ?? []).some((targetId) => flagged.has(targetId));
    if (armed !== (hunt.hunt_pir_armed === true)) {
      await updateHuntRunInformation(context, hunt.internal_id, { hunt_pir_armed: armed, hunt_pir_armed_at: armed ? now() : null });
      logApp.info(`[OPENCTI-MODULE] Hunt ${armed ? 'armed' : 'disarmed'} by its PIR targets`, { huntId: hunt.internal_id });
      if (armed && started < HUNT_CONFIG.maxRunsPerTick) {
        started += await startAutomaticRuns(context, hunt, HUNT_RUN_TRIGGER_STANDING);
      }
    }
  }
  return started;
};

interface StandingCandidate {
  hunt: BasicStoreEntityHunt;
  filters: FilterGroup | null;
  refIds: Set<string>;
  rising: boolean;
}

const isPulseRising = (entity: BasicStoreEntity & Record<string, unknown>) => {
  const attribute = schemaAttributesDefinition.getAttribute(entity.entity_type, PULSE_TREND_ATTRIBUTE);
  return !!attribute && String(entity[PULSE_TREND_ATTRIBUTE] ?? '').toLowerCase() === PULSE_TREND_RISING;
};

export const buildStandingCandidates = async (context: AuthContext, hunts: BasicStoreEntityHunt[]): Promise<StandingCandidate[]> => {
  const refInternalIds = Array.from(new Set(hunts.flatMap((hunt) => [
    ...(hunt[RELATION_HUNT_TARGETS] ?? []),
    ...(hunt[RELATION_HUNT_TECHNIQUES] ?? []),
    ...(hunt[RELATION_HUNT_SOURCES] ?? []),
  ])));
  const refs = refInternalIds.length > 0 ? await findByIds<BasicStoreEntity & Record<string, unknown>>(context, HUNT_MANAGER_USER, refInternalIds) : [];
  const refsById = new Map(refs.map((ref) => [ref.internal_id, ref]));
  const candidates: StandingCandidate[] = [];
  hunts.forEach((hunt) => {
    try {
      const huntRefs = [...(hunt[RELATION_HUNT_TARGETS] ?? []), ...(hunt[RELATION_HUNT_TECHNIQUES] ?? []), ...(hunt[RELATION_HUNT_SOURCES] ?? [])]
        .map((id) => refsById.get(id))
        .filter((ref): ref is BasicStoreEntity & Record<string, unknown> => !!ref);
      candidates.push({
        hunt,
        filters: parseHuntFilterGroup(hunt.trigger_filters, 'trigger_filters'),
        refIds: new Set(huntRefs.flatMap((ref) => [ref.standard_id, ...((ref.x_opencti_stix_ids as string[] | undefined) ?? [])])),
        rising: (hunt[RELATION_HUNT_TARGETS] ?? []).some((id) => {
          const target = refsById.get(id);
          return !!target && isPulseRising(target);
        }),
      });
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Standing hunt ignored, its trigger filters are invalid', { cause: error, huntId: hunt.internal_id });
    }
  });
  return candidates;
};

const collectValues = (value: unknown, into: string[]) => {
  if (typeof value === 'string') {
    into.push(value);
  } else if (Array.isArray(value)) {
    value.forEach((item) => (typeof item === 'string' ? into.push(item) : undefined));
  }
};

/**
 * Standard ids an event brings into the knowledge: the refs of a created object, the refs added by an update.
 */
export const eventTouchedRefs = (event: DataEvent): string[] => {
  const refs: string[] = [];
  const data = event.data as unknown as Record<string, unknown>;
  if (event.type === EVENT_TYPE_CREATE) {
    STANDING_REF_FIELDS.forEach((field) => collectValues(data[field], refs));
  } else if (event.type === EVENT_TYPE_UPDATE) {
    const patch = ((event as UpdateEvent).context?.patch ?? []) as Operation[];
    patch.forEach((operation) => {
      const field = operation.path.split('/')[1];
      if ((operation.op === 'add' || operation.op === 'replace') && STANDING_REF_FIELDS.includes(field)) {
        collectValues((operation as { value?: unknown }).value, refs);
      }
    });
  }
  return refs.slice(0, STANDING_MAX_REFS_PER_EVENT);
};

export const isStandingHuntTriggered = async (context: AuthContext, candidate: StandingCandidate, event: DataEvent) => {
  if (candidate.filters) {
    return isStixMatchFilterGroup(context, HUNT_MANAGER_USER, event.data, candidate.filters);
  }
  return eventTouchedRefs(event).some((ref) => candidate.refIds.has(ref));
};

const isRecentStandingRun = async (context: AuthContext, candidate: StandingCandidate) => {
  // Rising threats (Threat Pulse) halve the debounce window
  const debounce = candidate.rising ? HUNT_CONFIG.standingDebounceMinutes / 2 : HUNT_CONFIG.standingDebounceMinutes;
  const count = await elCount(context, HUNT_MANAGER_USER, READ_INDEX_INTERNAL_OBJECTS, {
    types: [ENTITY_TYPE_HUNT_RUN],
    filters: andFilters([
      { key: ['hunt_id'], values: [candidate.hunt.internal_id] },
      { key: ['hunt_run_trigger'], values: [HUNT_RUN_TRIGGER_STANDING] },
      { key: ['created_at'], values: [minutesAgo(debounce)], operator: FilterOperator.Gte },
    ]),
    noFiltersChecking: true,
  });
  return count > 0;
};

/**
 * Standing hunts: the stream events since the last tick are matched against the trigger filters of each standing hunt
 * (or, without filters, against the threats, techniques and sources of the hunt). Results of hunt connectors never
 * trigger a hunt. Triggered hunts run once per debounce window, rising threats first.
 */
export const processStandingHunts = async (context: AuthContext): Promise<number> => {
  const lastEventId = await redisGetManagerEventState(HUNT_MANAGER_STREAM_STATE);
  const hunts = await listHunts(context, [
    { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
    { key: ['hunt_schedule'], values: [HUNT_SCHEDULE_STANDING] },
  ]);
  const listening = hunts.filter((hunt) => !isWaitingForPir(hunt));
  if (!lastEventId || listening.length === 0) {
    // Nothing listens: the position follows the present so that a new standing hunt never replays the past
    await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, `${Date.now()}-0`);
    return 0;
  }
  const candidates = await buildStandingCandidates(context, listening);
  const huntConnectorUsers = new Set((await listHuntConnectors(context, false)).map((connector) => connector.connector_user_id).filter((id) => !!id));
  const triggered = new Map<string, StandingCandidate>();
  const processEvents = async (streamEvents: Array<SseEvent<DataEvent>>) => {
    for (let eventIndex = 0; eventIndex < streamEvents.length; eventIndex += 1) {
      const event = streamEvents[eventIndex].data;
      const originUser = event.origin?.user_id;
      const isHuntOrigin = !!originUser && (originUser === HUNT_MANAGER_USER.id || huntConnectorUsers.has(originUser));
      if ((event.type === EVENT_TYPE_CREATE || event.type === EVENT_TYPE_UPDATE) && !isHuntOrigin) {
        for (let index = 0; index < candidates.length; index += 1) {
          const candidate = candidates[index];
          if (!triggered.has(candidate.hunt.internal_id) && await isStandingHuntTriggered(context, candidate, event)) {
            triggered.set(candidate.hunt.internal_id, candidate);
          }
        }
      }
      await doYield();
    }
  };
  const { lastEventId: newLastEventId } = await fetchStreamEventsRangeFromEventId(lastEventId, processEvents, { streamBatchSize: HUNT_CONFIG.streamBatchSize });
  await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, newLastEventId);
  const ordered = Array.from(triggered.values()).sort((a, b) => Number(b.rising) - Number(a.rising));
  let started = 0;
  for (let index = 0; index < ordered.length && started < HUNT_CONFIG.maxRunsPerTick; index += 1) {
    if (!(await isRecentStandingRun(context, ordered[index]))) {
      started += await startAutomaticRuns(context, ordered[index].hunt, HUNT_RUN_TRIGGER_STANDING);
    }
  }
  return started;
};
// endregion

export interface HuntAutomationReport {
  expired: number;
  retried: number;
  dispatched: number;
  resumed: number;
  purged: number;
  scheduled: number;
  armed: number;
  standing: number;
}

/**
 * One tick of the hunt manager. The run lifecycle always applies (manual hunts are Community Edition), autonomous hunts
 * (schedules, PIR activation, standing hunts) only with an Enterprise Edition license.
 */
export const runHuntAutomation = async (context: AuthContext, isEnterprise: boolean): Promise<HuntAutomationReport> => {
  const report: HuntAutomationReport = { expired: 0, retried: 0, dispatched: 0, resumed: 0, purged: 0, scheduled: 0, armed: 0, standing: 0 };
  report.expired = await expireStaleHuntRuns(context);
  report.retried = await retryFailedHuntRuns(context);
  if (isEnterprise) {
    report.armed = await reconcilePirActivatedHunts(context);
    report.scheduled = await runScheduledHunts(context);
    report.standing = await processStandingHunts(context);
  } else {
    await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, `${Date.now()}-0`);
  }
  report.dispatched = await dispatchQueuedHuntRuns(context);
  report.resumed = await resumeSettledHuntPlaybooks(context);
  report.purged = await purgeExpiredHuntRuns(context);
  return report;
};
