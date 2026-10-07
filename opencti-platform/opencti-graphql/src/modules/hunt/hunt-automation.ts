import type { Operation } from 'fast-json-patch';
import type { GraphQLError } from 'graphql';
import type { AuthContext } from '../../types/user';
import type { BasicStoreEntity } from '../../types/store';
import type { DataEvent, SseEvent, UpdateEvent } from '../../types/event';
import { logApp } from '../../config/conf';
import { FUNCTIONAL_ERROR } from '../../config/errors';
import { deleteElementById, patchAttribute } from '../../database/middleware';
import { fullEntitiesList, internalLoadById, topEntitiesList } from '../../database/middleware-loader';
import { elCount } from '../../database/engine';
import { EVENT_TYPE_CREATE, EVENT_TYPE_UPDATE, offsetToCursor, READ_INDEX_INTERNAL_OBJECTS } from '../../database/utils';
import { redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { fetchStreamEventsRangeFromEventId } from '../../database/stream/stream-handler';
import { type FilterGroup, FilterMode, FilterOperator, type MutationPlaybookStepExecutionArgs, OrderingMode } from '../../generated/graphql';
import { RELATION_IN_PIR } from '../../schema/internalRelationship';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { isStixMatchFilterGroup } from '../../utils/filtering/filtering-stix/stix-filtering';
import { HUNT_MANAGER_USER, SYSTEM_USER } from '../../utils/access';
import type { BasicStoreEntityConnector } from '../../types/connector';
import { ENTITY_TYPE_CONNECTOR } from '../../schema/internalObject';
import { HUNT_MESSAGES } from './hunt-messages';
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
  HUNT_RUN_FINALIZABLE_STATUSES,
  HUNT_RUN_MODE_EXECUTE,
  HUNT_RUN_MODE_PREVIEW,
  HUNT_RUN_STATUS_FAILED,
  HUNT_RUN_STATUS_QUEUED,
  HUNT_RUN_STATUS_TIMEOUT,
  HUNT_RUN_TRIGGER_PIR,
  HUNT_RUN_TRIGGER_SCHEDULE,
  HUNT_RUN_TRIGGER_STANDING,
  type HuntPlaybookContext,
} from './huntRun/huntRun-types';
import {
  cancelHuntRun,
  computeRetryAt,
  createHuntRuns,
  expireHuntRun,
  isHuntRunFinalized,
  markHuntRunsOrphaned,
  reconcileHuntRunFinalization,
  releaseUnpublishedHuntRun,
  replaceHuntRun,
} from './huntRun/huntRun-domain';
import { dispatchHuntRun, listHuntConnectors } from './hunt-dispatch';
import { computeNextRunAt } from './hunt-schedule';
import { updateHuntRunInformation } from './hunt-stats';
import { HUNT_CONFIG, parseHuntFilterGroup } from './hunt-utils';
import { buildHuntPlaybookResume, executeHuntPlaybookResume, findPlaybookHuntRuns, isHuntRunGroupSettled } from './hunt-playbook';
import { purgeExpiredHuntHitRecords } from './huntHitRecord/huntHitRecord-domain';

export const HUNT_MANAGER_STREAM_STATE = 'hunt_manager';
const HUNT_MANAGER_STANDING_CURSOR_STATE = 'hunt_manager_standing_cursor';
// Soft coupling with Threat Pulse: entities whose community trend rises make their standing hunts react faster
export const PULSE_TREND_ATTRIBUTE = 'pulse_trend';
const PULSE_TREND_RISING = 'rising';
// Stream refs that, when added, mean that the knowledge around a hunt moved (a report adds a TTP, a sighting of a threat ...)
const STANDING_REF_FIELDS = ['object_refs', 'source_ref', 'target_ref', 'sighting_of_ref', 'where_sighted_refs'];
// A container can carry many thousands of refs: all are matched, the event loop is given back between two slices
const STANDING_REFS_PER_YIELD = 2000;

const minutesAgo = (minutes: number) => new Date(Date.now() - minutes * 60000).toISOString();

const andFilters = (filters: FilterGroup['filters'], filterGroups: FilterGroup[] = []): FilterGroup => ({ mode: FilterMode.And, filters, filterGroups });

const listRuns = (context: AuthContext, filters: FilterGroup['filters'], orderBy = 'created_at', first = HUNT_CONFIG.maxRunsPerTick, filterGroups: FilterGroup[] = []) => {
  return topEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
    first,
    orderBy,
    orderMode: OrderingMode.Asc,
    filters: andFilters(filters, filterGroups),
    noFiltersChecking: true,
  });
};

// Where a bounded scan resumes at the next tick; reset once a scan reached the last element, and on a restart of the manager
const scanCursors = new Map<string, string | undefined>();

/**
 * Every element of a type matching the filters, page by page. For phases whose filters do not drop the elements they
 * process (PIR arming, due scheduled hunts that started no run, standing hunts, the check of orphan runs), a bounded
 * first page would read the same oldest elements at every tick and never reach the others. With a scan name, a tick
 * reads at most `automationMaxPagesPerTick` pages and the next tick resumes after the last element read, starting over
 * once the last one was reached: every element is visited within a bounded number of ticks. A page handler returning how many elements it processed, fewer than the
 * page, stops the scan there: the next tick resumes after the last element it processed.
 */
const forEachPage = async <T extends BasicStoreEntity>(
  context: AuthContext,
  entityType: string,
  filters: FilterGroup,
  onPage: (elements: T[]) => Promise<number | void>,
  opts: { scan?: string; withoutRels?: boolean } = {},
) => {
  const { scan, withoutRels } = opts;
  let pages = 0;
  let position = scan ? scanCursors.get(scan) : undefined;
  let resumeAfter: string | undefined;
  await fullEntitiesList<T>(context, HUNT_MANAGER_USER, [entityType], {
    first: HUNT_CONFIG.automationPageSize,
    after: position,
    orderBy: 'created_at',
    orderMode: OrderingMode.Asc,
    filters,
    noFiltersChecking: true,
    withoutRels,
    callback: async (elements: T[]) => {
      const processed = (await onPage(elements)) ?? elements.length;
      pages += 1;
      if (processed < elements.length) {
        const lastProcessed = processed > 0 ? elements[processed - 1].sort : undefined;
        resumeAfter = lastProcessed ? offsetToCursor(lastProcessed) : position;
        return false;
      }
      const lastSort = elements[elements.length - 1]?.sort;
      position = lastSort ? offsetToCursor(lastSort) : position;
      // A page shorter than the page size is the last one: the scan starts over at the next tick
      if (scan && pages >= HUNT_CONFIG.automationMaxPagesPerTick && lastSort && elements.length >= HUNT_CONFIG.automationPageSize) {
        resumeAfter = offsetToCursor(lastSort);
        return false;
      }
      return true;
    },
  });
  if (scan) {
    scanCursors.set(scan, resumeAfter);
  }
};

const forEachHuntPage = (
  context: AuthContext,
  filters: FilterGroup['filters'],
  onPage: (hunts: BasicStoreEntityHunt[]) => Promise<void>,
  scan?: string,
) => forEachPage<BasicStoreEntityHunt>(context, ENTITY_TYPE_HUNT, andFilters(filters), onPage, { scan, withoutRels: false });

/**
 * The runs one manager tick may dispatch, shared by every phase of the tick (automatic retries, PIR activation, scheduled
 * and standing hunts, then the queued runs): each phase dispatches within what the previous ones left, so a tick never
 * dispatches more than `maxRunsPerTick` runs. A phase called alone gets a full budget.
 */
export interface HuntTickBudget {
  remaining: number;
}

export const newHuntTickBudget = (): HuntTickBudget => ({ remaining: HUNT_CONFIG.maxRunsPerTick });

/**
 * Starts the runs of a hunt within what is left of the tick budget: the runs of the targets beyond it are created queued
 * and dispatched by dispatchQueuedHuntRuns at the next ticks. Every registered hunt connector of the scope is targeted:
 * the run of a connector temporarily offline waits queued until it is back, or expires past the queue expiry. Returns the
 * number of runs started in this tick, or null when they could not be created for a transient reason (the engine, a lock).
 */
const startAutomaticRuns = async (context: AuthContext, hunt: BasicStoreEntityHunt, trigger: string, remainingBudget: number): Promise<number | null> => {
  try {
    const runs = await createHuntRuns(context, hunt, { trigger, dispatchLimit: remainingBudget, includeOfflineConnectors: true });
    if (runs.length === 0) {
      logApp.info('[OPENCTI-MODULE] Hunt not run, no hunt connector serves its scope', { huntId: hunt.internal_id, trigger });
    }
    return Math.min(runs.length, remainingBudget);
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Hunt automatic run failed to start', { cause: error, huntId: hunt.internal_id, trigger });
    // A refusal of the hunt itself (its status, its logic) is the same at the next tick
    return (error as GraphQLError)?.extensions?.code === FUNCTIONAL_ERROR ? 0 : null;
  }
};

// region run lifecycle (Community Edition: manual runs rely on it too)
/**
 * Runs reserved for their dispatch whose publication was never recorded: the process stopped between the reservation
 * and the publication of the message, or could not record the date of a publication. Past the grace of a dispatch in
 * progress, the reservation is released and the run is dispatched again at this tick under the work it already holds,
 * instead of waiting for the run timeout: a message that did reach its connector still reports to that work.
 */
export const requeueUnpublishedHuntRuns = async (context: AuthContext): Promise<number> => {
  const reservedBefore = minutesAgo(HUNT_CONFIG.dispatchRecoveryMinutes);
  const runs = await listRuns(context, [
    { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_QUEUED] },
    { key: ['dispatched_at'], values: [reservedBefore], operator: FilterOperator.Lte },
    { key: ['published_at'], values: [], operator: FilterOperator.Nil },
  ], 'dispatched_at');
  let requeued = 0;
  for (let index = 0; index < runs.length; index += 1) {
    const run = runs[index];
    try {
      // Read again under the transition lock of the run: the listing may be older than a report of its connector
      if (await releaseUnpublishedHuntRun(context, run, reservedBefore)) {
        requeued += 1;
        logApp.warn('[OPENCTI-MODULE] Hunt run publication not recorded, run queued again under its work', { runId: run.internal_id, workId: run.work_id ?? null });
      }
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt run reservation cannot be released, retried at the next tick', { cause: error, runId: run.internal_id });
    }
  }
  return requeued;
};

// The orphan runs of one page of active runs, cancelled: their hunt or their connector no longer exists
const cancelOrphanRunsOfPage = async (context: AuthContext, runs: BasicStoreEntityHuntRun[]): Promise<number> => {
  const huntIds = Array.from(new Set(runs.map((run) => run.hunt_id)));
  const connectorIds = Array.from(new Set(runs.map((run) => run.connector_id).filter((id): id is string => !!id)));
  const [hunts, connectors] = await Promise.all([
    findByIds<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, huntIds, { type: ENTITY_TYPE_HUNT }),
    findByIds<BasicStoreEntityConnector>(context, SYSTEM_USER, connectorIds, { type: ENTITY_TYPE_CONNECTOR }),
  ]);
  const existingHunts = new Set(hunts.map((hunt) => hunt.internal_id));
  const connectorsById = new Map(connectors.map((connector) => [connector.internal_id, connector]));
  let cancelled = 0;
  for (let index = 0; index < runs.length; index += 1) {
    const run = runs[index];
    const connector = run.connector_id ? connectorsById.get(run.connector_id) : undefined;
    let reason: string | null = null;
    if (!existingHunts.has(run.hunt_id)) {
      reason = HUNT_MESSAGES.runCancelledHuntDeleted;
    } else if (run.connector_id && (!connector || new Date(run.created_at).getTime() < new Date(connector.created_at).getTime())) {
      reason = HUNT_MESSAGES.runCancelledConnectorDeleted;
    }
    if (reason) {
      try {
        if (await cancelHuntRun(context, run.internal_id, reason)) {
          cancelled += 1;
        }
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Orphan hunt run cannot be cancelled, retried at the next tick', { cause: error, runId: run.internal_id });
      }
    }
  }
  return cancelled;
};

/**
 * Runs a deleted hunt or hunt connector left behind, whatever deleted it (the trash, a bulk deletion, a synchronization):
 * the runs still waiting, running or planning a retry whose hunt no longer exists, or whose connector no longer exists or
 * was registered again since the run was created (a redeployed connector reusing the id), are cancelled. The deletion of
 * a hunt or a hunt connector through the API cancels its runs at once: this check only catches the other deletions, so it
 * reads the active runs page by page and at most `automationMaxPagesPerTick` pages per tick, resuming at the next tick.
 */
export const cancelOrphanHuntRuns = async (context: AuthContext): Promise<number> => {
  let cancelled = 0;
  const filters = andFilters([], [{
    mode: FilterMode.Or,
    filters: [
      { key: ['hunt_run_status'], values: HUNT_RUN_ACTIVE_STATUSES },
      { key: ['next_retry_at'], values: [], operator: FilterOperator.NotNil },
    ],
    filterGroups: [],
  }]);
  await forEachPage<BasicStoreEntityHuntRun>(context, ENTITY_TYPE_HUNT_RUN, filters, async (runs) => {
    cancelled += await cancelOrphanRunsOfPage(context, runs);
  }, { scan: 'orphan-runs' });
  return cancelled;
};

/**
 * Keeps the flag the statistics leave the runs of deleted hunts out with, whatever deleted the hunt (the trash, a bulk
 * deletion, a synchronization) or brought it back (a restore from the trash); the deletion of a hunt through the API
 * flags its runs at once. Reads every run page by page, at most `automationMaxPagesPerTick` pages per tick, resuming at
 * the next tick; each page loads the hunts of its own runs, and a hunt whose runs disagree is flagged in one update.
 * Returns the number of hunts whose runs were flagged or cleared.
 */
export const reconcileOrphanedHuntRuns = async (context: AuthContext): Promise<number> => {
  let reconciled = 0;
  await forEachPage<BasicStoreEntityHuntRun>(context, ENTITY_TYPE_HUNT_RUN, andFilters([]), async (runs) => {
    const huntIds = Array.from(new Set(runs.map((run) => run.hunt_id)));
    const existing = new Set((await findByIds<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, huntIds, { type: ENTITY_TYPE_HUNT })).map((hunt) => hunt.internal_id));
    const flag = new Set<string>();
    const clear = new Set<string>();
    runs.forEach((run) => {
      const orphaned = !existing.has(run.hunt_id);
      if (orphaned !== (run.hunt_orphaned === true)) {
        (orphaned ? flag : clear).add(run.hunt_id);
      }
    });
    try {
      await markHuntRunsOrphaned(Array.from(flag), true);
      await markHuntRunsOrphaned(Array.from(clear), false);
      reconciled += flag.size + clear.size;
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Runs of deleted hunts cannot be flagged, flagged at the next pass of the scan', { cause: error, hunts: flag.size + clear.size });
    }
  }, { scan: 'orphaned-runs' });
  return reconciled;
};

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
        logApp.warn('[OPENCTI-MODULE] Hunt run expiration failed, retried at the next tick', { cause: error, runId: runs[index].internal_id });
      }
    }
  }
  return expired;
};

/**
 * Automatic retries of failed or timed out runs once their backoff elapsed: a new run on the same connector and window,
 * with the next attempt number. Runs of draft or retired hunts are given up, as well as runs whose connector stays down
 * beyond the queue expiry. A retry is dispatched as soon as it is created: once the tick budget is spent, the runs left
 * keep their planned retry for the next tick.
 */
export const retryFailedHuntRuns = async (context: AuthContext, budget: HuntTickBudget = newHuntTickBudget()): Promise<number> => {
  const runs = await listRuns(context, [
    { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_FAILED, HUNT_RUN_STATUS_TIMEOUT] },
    { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
    { key: ['next_retry_at'], values: [now()], operator: FilterOperator.Lte },
  ], 'next_retry_at');
  let retried = 0;
  for (let index = 0; index < runs.length; index += 1) {
    const listed = runs[index];
    const hunt = await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, listed.hunt_id, { type: ENTITY_TYPE_HUNT });
    const expiredSince = listed.completed_at ? Date.now() - new Date(listed.completed_at).getTime() : 0;
    const giveUp = !hunt || [HUNT_STATUS_DRAFT, HUNT_STATUS_RETIRED].includes(hunt.hunt_status) || expiredSince > HUNT_CONFIG.queueExpiryHours * 3600000;
    if (!giveUp && budget.remaining <= 0) {
      continue;
    }
    try {
      if (giveUp) {
        await patchAttribute(context, HUNT_MANAGER_USER, listed.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: null });
      } else {
        // Under the run lock: a retry an analyst already started, or a replacement created before a crash, is not
        // created again
        const { planned, created, replacement } = await replaceHuntRun(context, hunt, listed.internal_id, { automatic: true });
        if (created) {
          retried += 1;
          budget.remaining -= 1;
        } else if (planned && !replacement) {
          // Connector down: try again later, the queue expiry bounds the wait (a later replacement still finds this one)
          await patchAttribute(context, HUNT_MANAGER_USER, listed.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: computeRetryAt(listed.attempt ?? 1) });
        }
      }
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt run retry failed, planned again', { cause: error, runId: listed.internal_id });
      await patchAttribute(context, HUNT_MANAGER_USER, listed.internal_id, ENTITY_TYPE_HUNT_RUN, { next_retry_at: computeRetryAt(listed.attempt ?? 1) })
        .catch((restoreError) => logApp.warn('[OPENCTI-MODULE] Hunt run retry cannot be planned again, retried at the next tick', { cause: restoreError, runId: listed.internal_id }));
    }
  }
  return retried;
};

// A finalization runs right after the report that terminates a run: older than this, an unfinalized run was interrupted
const FINALIZATION_GRACE_MINUTES = 2;
// A run whose finalization steps keep failing for this long gets its verdict anyway (the failures stay in the logs)
const FINALIZATION_GIVE_UP_MINUTES = 60;

/**
 * Terminated executed runs whose finalization (incident draft, automatic verdict, statistics) was interrupted, for
 * instance by an engine error after the terminal report was stored: their finalization is completed.
 */
export const finalizeInterruptedHuntRuns = async (context: AuthContext): Promise<number> => {
  const runs = await listRuns(context, [
    { key: ['hunt_run_status'], values: HUNT_RUN_FINALIZABLE_STATUSES },
    { key: ['hunt_run_mode'], values: [HUNT_RUN_MODE_EXECUTE] },
    { key: ['verdict_source'], values: [], operator: FilterOperator.Nil },
    { key: ['completed_at'], values: [minutesAgo(FINALIZATION_GRACE_MINUTES)], operator: FilterOperator.Lte },
  ], 'completed_at');
  const giveUpBefore = new Date(minutesAgo(FINALIZATION_GIVE_UP_MINUTES)).getTime();
  let finalized = 0;
  for (let index = 0; index < runs.length; index += 1) {
    try {
      const force = !!runs[index].completed_at && new Date(runs[index].completed_at as string).getTime() <= giveUpBefore;
      const run = await reconcileHuntRunFinalization(context, runs[index], force);
      if (isHuntRunFinalized(run)) {
        finalized += 1;
      }
    } catch (error) {
      logApp.warn('[OPENCTI-MODULE] Hunt run finalization could not be completed, retried at the next tick', { cause: error, runId: runs[index].internal_id });
    }
  }
  return finalized;
};

/**
 * Queued runs deferred by the connector budgets or a connector outage, translation previews first (an analyst waits
 * for them), then the oldest runs. The queue is read page by page and a connector that defers a run is skipped for the
 * rest of the tick, so the runs waiting on a saturated or offline connector never hold back the other connectors.
 * Every run the tick works on counts against its budget, a deferred or failed dispatch included, and a connector whose
 * dispatch fails is skipped for the rest of the tick too: a saturated or offline connector, or an outage of work
 * creation or queue publication, costs one attempt per connector and tick, never a pass over the whole queue.
 */
export const dispatchQueuedHuntRuns = async (context: AuthContext, budget: HuntTickBudget = newHuntTickBudget()): Promise<number> => {
  const hunts = new Map<string, BasicStoreEntityHunt | undefined>();
  const deferringConnectors = new Set<string>();
  let dispatched = 0;
  const dispatchPage = async (runs: BasicStoreEntityHuntRun[]) => {
    for (let index = 0; index < runs.length; index += 1) {
      if (budget.remaining <= 0) {
        return false;
      }
      const run = runs[index];
      if (!run.connector_id || !deferringConnectors.has(run.connector_id)) {
        if (!hunts.has(run.hunt_id)) {
          hunts.set(run.hunt_id, await internalLoadById<BasicStoreEntityHunt>(context, HUNT_MANAGER_USER, run.hunt_id, { type: ENTITY_TYPE_HUNT }) ?? undefined);
        }
        const hunt = hunts.get(run.hunt_id);
        try {
          if (!hunt) {
            await cancelHuntRun(context, run.internal_id, HUNT_MESSAGES.runCancelledHuntDeleted);
          } else if (await dispatchHuntRun(context, run, hunt)) {
            dispatched += 1;
          } else if (run.connector_id) {
            deferringConnectors.add(run.connector_id);
          }
        } catch (error) {
          if (run.connector_id) {
            deferringConnectors.add(run.connector_id);
          }
          logApp.warn('[OPENCTI-MODULE] Hunt run dispatch failed, its connector is skipped until the next tick', { cause: error, runId: run.internal_id, connectorId: run.connector_id });
        }
        budget.remaining -= 1;
      }
    }
    return true;
  };
  const modes = [HUNT_RUN_MODE_PREVIEW, HUNT_RUN_MODE_EXECUTE];
  for (let index = 0; index < modes.length && budget.remaining > 0; index += 1) {
    // Once a connector defers, the queue is read again without its runs: the runs of an offline or saturated connector
    // are never paged through, a tick reads at most one more page per deferring connector
    let rescan = true;
    while (rescan && budget.remaining > 0) {
      rescan = false;
      const skipped = Array.from(deferringConnectors);
      await fullEntitiesList<BasicStoreEntityHuntRun>(context, HUNT_MANAGER_USER, [ENTITY_TYPE_HUNT_RUN], {
        first: HUNT_CONFIG.maxRunsPerTick,
        orderBy: 'created_at',
        orderMode: OrderingMode.Asc,
        filters: andFilters([
          { key: ['hunt_run_status'], values: [HUNT_RUN_STATUS_QUEUED] },
          { key: ['dispatched_at'], values: [], operator: FilterOperator.Nil },
          { key: ['hunt_run_mode'], values: [modes[index]] },
          ...(skipped.length > 0 ? [{ key: ['connector_id'], values: skipped, operator: FilterOperator.NotEq, mode: FilterMode.And }] : []),
        ]),
        noFiltersChecking: true,
        callback: async (runs: BasicStoreEntityHuntRun[]) => {
          const deferringBefore = deferringConnectors.size;
          const proceed = await dispatchPage(runs);
          if (proceed && deferringConnectors.size > deferringBefore) {
            rescan = true;
            return false;
          }
          return proceed;
        },
      });
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
        logApp.warn('[OPENCTI-MODULE] Hunt run purge failed, retried at the next tick', { cause: error, runId: runs[index].internal_id });
      }
    }
  }
  // The known hits live as long as the runs that found them
  try {
    await purgeExpiredHuntHitRecords(minutesAgo(HUNT_CONFIG.runRetentionDays * 24 * 60));
  } catch (error) {
    logApp.warn('[OPENCTI-MODULE] Hunt known hits purge failed, retried at the next tick', { cause: error });
  }
  return purged;
};

/**
 * Continuation of the playbooks waiting on hunt steps: once every run of a step is settled, the step resumes, at most
 * once like any playbook step. The step is built first, then its run hands the continuation over, and only then the
 * step executes: a step that could not be built or handed over stays with its run for the next tick, and a step that
 * fails or is interrupted once handed over is never executed again (the playbook execution shows its failure, as for any
 * step). The runs holding a continuation are scanned from where the previous tick stopped, at most `maxRunsPerTick`
 * resumes per tick, so that the steps still waiting never keep the settled ones from resuming.
 */
export const resumeSettledHuntPlaybooks = async (context: AuthContext): Promise<number> => {
  let resumed = 0;
  const resumePage = async (leaders: BasicStoreEntityHuntRun[]) => {
    for (let index = 0; index < leaders.length; index += 1) {
      if (resumed >= HUNT_CONFIG.maxRunsPerTick) {
        return index;
      }
      const leader = leaders[index];
      let handedOver: MutationPlaybookStepExecutionArgs | undefined;
      try {
        const group = leader.playbook_execution_id
          ? await findPlaybookHuntRuns(context, { executionId: leader.playbook_execution_id, instanceId: leader.playbook_instance_id, stepId: leader.playbook_step_id })
          : [leader];
        if (isHuntRunGroupSettled(group) && leader.playbook_context) {
          const step = await buildHuntPlaybookResume(context, JSON.parse(leader.playbook_context) as HuntPlaybookContext, group);
          await patchAttribute(context, HUNT_MANAGER_USER, leader.internal_id, ENTITY_TYPE_HUNT_RUN, { playbook_leader: false, playbook_resumed_at: now() });
          handedOver = step;
        }
      } catch (error) {
        logApp.warn('[OPENCTI-MODULE] Hunt playbook resume failed, the step waits for the next tick', { cause: error, runId: leader.internal_id, playbookId: leader.playbook_id });
      }
      if (handedOver) {
        resumed += 1;
        await executeHuntPlaybookResume(context, handedOver)
          .catch((error) => logApp.error('[OPENCTI-MODULE] Hunt playbook step failed once handed over', { cause: error, runId: leader.internal_id, playbookId: leader.playbook_id }));
      }
    }
    return leaders.length;
  };
  await forEachPage<BasicStoreEntityHuntRun>(context, ENTITY_TYPE_HUNT_RUN, andFilters([{ key: ['playbook_leader'], values: ['true'] }]), resumePage, { scan: 'playbook-leaders' });
  return resumed;
};
// endregion

// region autonomous hunts (Enterprise Edition)
const isWaitingForPir = (hunt: BasicStoreEntityHunt) => hunt.hunt_pir_activation === true && hunt.hunt_pir_armed !== true;

/**
 * Cron hunts: due hunts run (unless their PIR activation is not armed) and their next occurrence is computed from now,
 * so that an outage never replays the missed occurrences. An occurrence that started no run (its runs could not be
 * created, or no hunt connector serves the scope yet) stays due for the next tick, as the standing and PIR triggers
 * do: the due hunts are scanned in turn, so the ones that cannot run never hold back the others. Hunts approved from a
 * draft get their first occurrence here.
 */
export const runScheduledHunts = async (context: AuthContext, budget: HuntTickBudget = newHuntTickBudget()): Promise<number> => {
  let started = 0;
  const filters = andFilters([
    { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
    { key: ['hunt_schedule'], values: [HUNT_SCHEDULE_MANUAL, HUNT_SCHEDULE_STANDING], operator: FilterOperator.NotEq, mode: FilterMode.And },
  ], [{
    mode: FilterMode.Or,
    filters: [
      { key: ['next_run_at'], values: [now()], operator: FilterOperator.Lte },
      { key: ['next_run_at'], values: [], operator: FilterOperator.Nil },
    ],
    filterGroups: [],
  }]);
  await forEachPage<BasicStoreEntityHunt>(context, ENTITY_TYPE_HUNT, filters, async (hunts) => {
    for (let index = 0; index < hunts.length; index += 1) {
      // Once the tick budget is spent the remaining hunts keep their due occurrence, the next tick resumes after this one
      if (budget.remaining <= 0) {
        return index;
      }
      const hunt = hunts[index];
      // A first occurrence, or one falling while the PIR activation is disarmed, is planned without running
      const due = !!hunt.next_run_at && !isWaitingForPir(hunt);
      const runs = due ? await startAutomaticRuns(context, hunt, HUNT_RUN_TRIGGER_SCHEDULE, budget.remaining) : 0;
      if (runs !== null && (!due || runs > 0)) {
        started += runs;
        budget.remaining -= runs;
        const nextRunAt = computeNextRunAt(hunt.hunt_schedule, new Date());
        await updateHuntRunInformation(context, hunt.internal_id, { next_run_at: nextRunAt ? nextRunAt.toISOString() : null });
      }
    }
    return hunts.length;
  }, { scan: 'scheduled-hunts', withoutRels: false });
  return started;
};

/**
 * PIR activation: a hunt with PIR activation is armed while one of its targets is flagged by a PIR. Arming runs the hunt
 * once; while armed its schedule and standing triggers apply, disarmed it waits. The hunt status stays the analyst's.
 * Disarming drops the standing trigger the hunt still holds, as the occurrences of a cron hunt that fall while it is
 * disarmed are dropped: once armed again, the arming run covers its time window.
 */
export const reconcilePirActivatedHunts = async (context: AuthContext, budget: HuntTickBudget = newHuntTickBudget()): Promise<number> => {
  let started = 0;
  await forEachHuntPage(context, [
    { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
    { key: ['hunt_pir_activation'], values: ['true'] },
  ], async (hunts) => {
    const targetIds = Array.from(new Set(hunts.flatMap((hunt) => hunt[RELATION_HUNT_TARGETS] ?? [])));
    const targets = targetIds.length > 0 ? await findByIds<BasicStoreEntity>(context, HUNT_MANAGER_USER, targetIds) : [];
    const flagged = new Set(targets.filter((target) => (target[RELATION_IN_PIR] ?? []).length > 0).map((target) => target.internal_id));
    for (let index = 0; index < hunts.length; index += 1) {
      const hunt = hunts[index];
      const armed = (hunt[RELATION_HUNT_TARGETS] ?? []).some((targetId) => flagged.has(targetId));
      if (!armed && hunt.hunt_pir_armed === true) {
        const pendingTrigger = hunt.hunt_schedule === HUNT_SCHEDULE_STANDING ? { next_run_at: null } : {};
        await updateHuntRunInformation(context, hunt.internal_id, { hunt_pir_armed: false, hunt_pir_armed_at: null, ...pendingTrigger });
        logApp.info('[OPENCTI-MODULE] Hunt disarmed by its PIR targets', { huntId: hunt.internal_id });
      } else if (armed && hunt.hunt_pir_armed !== true && budget.remaining > 0) {
        // Armed once its arming run started: a run the tick budget or a missing connector refused is tried at the next tick
        const runs = await startAutomaticRuns(context, hunt, HUNT_RUN_TRIGGER_PIR, budget.remaining) ?? 0;
        if (runs > 0) {
          started += runs;
          budget.remaining -= runs;
          await updateHuntRunInformation(context, hunt.internal_id, { hunt_pir_armed: true, hunt_pir_armed_at: now() });
          logApp.info('[OPENCTI-MODULE] Hunt armed by its PIR targets', { huntId: hunt.internal_id });
        }
      }
    }
  }, 'pir_activation');
  return started;
};

export interface StandingCandidate {
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
  return refs;
};

export const isStandingHuntTriggered = async (context: AuthContext, candidate: StandingCandidate, event: DataEvent) => {
  if (candidate.filters) {
    return isStixMatchFilterGroup(context, HUNT_MANAGER_USER, event.data, candidate.filters);
  }
  return eventTouchedRefs(event).some((ref) => candidate.refIds.has(ref));
};

const compareIds = (a: string, b: string) => (a < b ? -1 : Number(a > b));

/**
 * Standing hunts split for matching: those without trigger filters by the refs that trigger them, the others apart, in
 * the order of their ids that an event matched over several ticks resumes from.
 */
export const indexStandingCandidates = (candidates: StandingCandidate[]) => {
  const byRef = new Map<string, StandingCandidate[]>();
  candidates.filter((candidate) => !candidate.filters).forEach((candidate) => {
    candidate.refIds.forEach((ref) => byRef.set(ref, [...(byRef.get(ref) ?? []), candidate]));
  });
  const filtered = candidates.filter((candidate) => !!candidate.filters).sort((a, b) => compareIds(a.hunt.internal_id, b.hunt.internal_id));
  return { byRef, filtered };
};

/** An event whose trigger filters a tick evaluated in part: the next tick evaluates the hunts after the last one. */
export interface StandingCursor {
  eventId: string;
  afterHuntId: string;
}

export interface StandingMatch {
  triggered: Map<string, StandingCandidate>;
  evaluations: number;
  budgetSpent: boolean;
  matchedEventId: string | null;
  partial?: StandingCursor | null;
}

/**
 * Matches knowledge events against standing hunts. Hunts without trigger filters are found from the refs an event
 * touches, never by trying every hunt; trigger filters are evaluated within a budget. Matching stops before the event
 * that would exceed it, `matchedEventId` being the last event fully matched. The first event needing more evaluations
 * than the whole budget is evaluated up to the budget, `partial` naming the last hunt evaluated, and resumed from there
 * by the next tick (`resume`): a tick never exceeds its budget and always moves forward.
 */
export const matchStandingEvents = async (
  indexed: ReturnType<typeof indexStandingCandidates>,
  streamEvents: Array<SseEvent<DataEvent>>,
  match: StandingMatch,
  opts: {
    budget: number;
    resume?: StandingCursor | null;
    isIgnored: (event: DataEvent) => boolean;
    evaluate: (candidate: StandingCandidate, event: DataEvent) => Promise<boolean>;
  },
) => {
  for (let eventIndex = 0; eventIndex < streamEvents.length && !match.budgetSpent; eventIndex += 1) {
    const { id, data: event } = streamEvents[eventIndex];
    if ((event.type === EVENT_TYPE_CREATE || event.type === EVENT_TYPE_UPDATE) && !opts.isIgnored(event)) {
      const after = opts.resume?.eventId === id ? opts.resume.afterHuntId : null;
      const toEvaluate = indexed.filtered.filter((candidate) => !match.triggered.has(candidate.hunt.internal_id)
        && (after === null || compareIds(candidate.hunt.internal_id, after) > 0));
      const exceeds = match.evaluations + toEvaluate.length > opts.budget;
      if (exceeds && match.evaluations > 0) {
        match.budgetSpent = true;
        return;
      }
      const refs = eventTouchedRefs(event);
      for (let refIndex = 0; refIndex < refs.length; refIndex += 1) {
        (indexed.byRef.get(refs[refIndex]) ?? []).forEach((candidate) => match.triggered.set(candidate.hunt.internal_id, candidate));
        if ((refIndex + 1) % STANDING_REFS_PER_YIELD === 0) {
          await doYield();
        }
      }
      const evaluated = exceeds ? Math.max(1, opts.budget) : toEvaluate.length;
      for (let index = 0; index < evaluated; index += 1) {
        match.evaluations += 1;
        if (await opts.evaluate(toEvaluate[index], event)) {
          match.triggered.set(toEvaluate[index].hunt.internal_id, toEvaluate[index]);
        }
      }
      if (evaluated < toEvaluate.length) {
        match.partial = { eventId: id, afterHuntId: toEvaluate[evaluated - 1].hunt.internal_id };
        match.budgetSpent = true;
        return;
      }
    }
    match.matchedEventId = id;
    await doYield();
  }
};

const parseStandingCursor = (state: string | null): StandingCursor | null => {
  try {
    const cursor = state ? JSON.parse(state) : null;
    return typeof cursor?.eventId === 'string' && typeof cursor?.afterHuntId === 'string' ? cursor : null;
  } catch {
    return null;
  }
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
 * (or, without filters, against the threats, techniques and sources of the hunt), within a per-tick budget of filter
 * evaluations. Results of hunt connectors never trigger a hunt. Triggered hunts run once per debounce window, rising
 * threats first; a trigger stays pending on its hunt until a tick serves it.
 */
export const processStandingHunts = async (context: AuthContext, budget: HuntTickBudget = newHuntTickBudget()): Promise<number> => {
  const lastEventId = await redisGetManagerEventState(HUNT_MANAGER_STREAM_STATE);
  // Every standing hunt sees the events of the tick: the stream position is shared, events are read once, so this scan
  // is never bounded (a hunt left out of a tick would miss its events for good); the matching is, by its evaluation budget
  const listening: BasicStoreEntityHunt[] = [];
  await forEachHuntPage(context, [
    { key: ['hunt_status'], values: [HUNT_STATUS_ACTIVE] },
    { key: ['hunt_schedule'], values: [HUNT_SCHEDULE_STANDING] },
  ], async (hunts) => {
    listening.push(...hunts.filter((hunt) => !isWaitingForPir(hunt)));
  });
  if (!lastEventId || listening.length === 0) {
    // Nothing listens: the position follows the present so that a new standing hunt never replays the past
    await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, `${Date.now()}-0`);
    return 0;
  }
  const candidates = await buildStandingCandidates(context, listening);
  const indexed = indexStandingCandidates(candidates);
  const huntConnectorUsers = new Set((await listHuntConnectors(context, false)).map((connector) => connector.connector_user_id).filter((id) => !!id));
  const isHuntOrigin = (event: DataEvent) => {
    const originUser = event.origin?.user_id;
    return !!originUser && (originUser === HUNT_MANAGER_USER.id || huntConnectorUsers.has(originUser));
  };
  const match: StandingMatch = { triggered: new Map(), evaluations: 0, budgetSpent: false, matchedEventId: null, partial: null };
  const resume = parseStandingCursor(await redisGetManagerEventState(HUNT_MANAGER_STANDING_CURSOR_STATE));
  const processEvents = (streamEvents: Array<SseEvent<DataEvent>>) => matchStandingEvents(indexed, streamEvents, match, {
    budget: HUNT_CONFIG.standingFilterEvaluationsPerTick,
    resume,
    isIgnored: isHuntOrigin,
    evaluate: (candidate, event) => isStandingHuntTriggered(context, candidate, event),
  });
  const { lastEventId: rangeLastEventId } = await fetchStreamEventsRangeFromEventId(lastEventId, processEvents, { streamBatchSize: HUNT_CONFIG.streamBatchSize });
  // A spent budget leaves the position after the last event fully matched: the next tick resumes from there
  const newLastEventId = match.budgetSpent ? (match.matchedEventId ?? lastEventId) : rangeLastEventId;
  const { triggered } = match;
  // A trigger is kept on its hunt (its next run is due now) before the stream position moves past the events that raised
  // it, and cleared once served: a trigger beyond the tick budget, or whose run could not start, is served by a later tick
  const pending = new Set(listening
    .filter((hunt) => !!hunt.next_run_at && new Date(hunt.next_run_at).getTime() <= Date.now())
    .map((hunt) => hunt.internal_id));
  const triggeredAt = now();
  const newlyTriggered = Array.from(triggered.keys()).filter((huntId) => !pending.has(huntId));
  for (let index = 0; index < newlyTriggered.length; index += 1) {
    await updateHuntRunInformation(context, newlyTriggered[index], { next_run_at: triggeredAt });
    pending.add(newlyTriggered[index]);
  }
  await redisSetManagerEventState(HUNT_MANAGER_STANDING_CURSOR_STATE, match.partial ? JSON.stringify(match.partial) : '');
  await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, newLastEventId);
  const candidatesById = new Map(candidates.map((candidate) => [candidate.hunt.internal_id, candidate]));
  const ordered = Array.from(pending)
    .map((huntId) => candidatesById.get(huntId))
    .filter((candidate): candidate is StandingCandidate => !!candidate)
    .sort((a, b) => Number(b.rising) - Number(a.rising));
  let started = 0;
  for (let index = 0; index < ordered.length && budget.remaining > 0; index += 1) {
    const candidate = ordered[index];
    // A standing run within the debounce window serves the trigger
    let served = true;
    if (!(await isRecentStandingRun(context, candidate))) {
      const runs = await startAutomaticRuns(context, candidate.hunt, HUNT_RUN_TRIGGER_STANDING, budget.remaining) ?? 0;
      started += runs;
      budget.remaining -= runs;
      served = runs > 0;
    }
    if (served) {
      await updateHuntRunInformation(context, candidate.hunt.internal_id, { next_run_at: null });
    }
  }
  return started;
};
// endregion

export interface HuntAutomationReport {
  cancelled: number;
  orphaned: number;
  requeued: number;
  expired: number;
  finalized: number;
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
  const report: HuntAutomationReport = {
    cancelled: 0, orphaned: 0, requeued: 0, expired: 0, finalized: 0, retried: 0, dispatched: 0, resumed: 0, purged: 0, scheduled: 0, armed: 0, standing: 0,
  };
  // First: the runs of deleted hunts and connectors free their slots before anything is dispatched or expired
  report.cancelled = await cancelOrphanHuntRuns(context);
  report.orphaned = await reconcileOrphanedHuntRuns(context);
  report.requeued = await requeueUnpublishedHuntRuns(context);
  report.expired = await expireStaleHuntRuns(context);
  report.finalized = await finalizeInterruptedHuntRuns(context);
  const budget = newHuntTickBudget();
  report.retried = await retryFailedHuntRuns(context, budget);
  if (isEnterprise) {
    report.armed = await reconcilePirActivatedHunts(context, budget);
    report.scheduled = await runScheduledHunts(context, budget);
    report.standing = await processStandingHunts(context, budget);
  } else {
    await redisSetManagerEventState(HUNT_MANAGER_STREAM_STATE, `${Date.now()}-0`);
  }
  report.dispatched = await dispatchQueuedHuntRuns(context, budget);
  report.resumed = await resumeSettledHuntPlaybooks(context);
  report.purged = await purgeExpiredHuntRuns(context);
  return report;
};
