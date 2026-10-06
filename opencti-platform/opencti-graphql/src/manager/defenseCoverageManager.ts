import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { lockResources } from '../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../config/errors';
import type { DataEvent, SseEvent } from '../types/event';
import { RELATION_DETECTS, RELATION_HAS_COVERED, RELATION_INDICATES, RELATION_MITIGATES } from '../schema/stixCoreRelationship';
import { computeDefenseCoverage, findTechniquesOfSources } from '../modules/defenseCoverage/defenseCoverage-compute';
import { collectDefenseImpact } from '../modules/defenseCoverage/defenseCoverage-impact';
import { deliverPendingDefenseLevelChanges } from '../modules/defenseCoverage/defenseCoverage-notification';
import { trackPendingValidationRequests } from '../modules/defenseCoverage/defenseCoverage-domain';
import { redisGetManagerEventState, redisSetManagerEventState } from '../database/redis';
import {
  bumpDefenseCoverageVersion,
  bumpDefenseOverlayVersion,
  bumpDefenseThreatsVersion,
  clearFullComputationRunning,
  consumeFullComputationRequest,
  getLastFullComputation,
  listPendingLevelChanges,
  markFullComputationRunning,
  requestFullDefenseCoverageComputation,
  setLastFullComputation,
} from '../modules/defenseCoverage/defenseCoverage-state';
import { addDefenseGapClosedCount } from './telemetryManager';
import type { AuthContext } from '../types/user';

const DEFENSE_COVERAGE_MANAGER_ID = 'DEFENSE_COVERAGE_MANAGER';
const DEFENSE_COVERAGE_MANAGER_LABEL = 'Defense coverage manager';
const DEFENSE_COVERAGE_MANAGER_CONTEXT = 'defense_coverage_manager';

const DEFENSE_COVERAGE_MANAGER_ENABLED = booleanConf('defense_coverage_manager:enabled', true);
const DEFENSE_COVERAGE_MANAGER_KEY = conf.get('defense_coverage_manager:lock_key') || 'defense_coverage_manager_lock';
const DEFENSE_COVERAGE_MANAGER_STREAM_KEY = conf.get('defense_coverage_manager:stream_lock_key') || 'defense_coverage_manager_stream_lock';
const DEFENSE_COVERAGE_COMPUTE_KEY = 'defense_coverage_compute_lock';
const SCHEDULE_TIME = conf.get('defense_coverage_manager:interval') || 300000; // 5 minutes
const FULL_COMPUTATION_INTERVAL = conf.get('defense_coverage_manager:full_computation_interval') || 86400000; // 1 day
const STREAM_SCHEDULE_TIME = conf.get('defense_coverage_manager:stream_interval') || 10000;
const STREAM_BUFFER_TIME = conf.get('defense_coverage_manager:stream_buffer_time') || 10000;
const MAX_INCREMENTAL_TECHNIQUES = conf.get('defense_coverage_manager:max_incremental_techniques') || 300;
const COMPUTE_LOCK_RETRY_COUNT = 30;

const runComputation = async (context: AuthContext, attackPatternIds?: string[]) => {
  let lock;
  try {
    lock = await lockResources([DEFENSE_COVERAGE_COMPUTE_KEY], { retryCount: COMPUTE_LOCK_RETRY_COUNT });
    const result = await computeDefenseCoverage(context, SYSTEM_USER, { attackPatternIds });
    // The coverage and the gaps are stored: a usage counter that cannot be written must not request a recomputation
    try {
      await addDefenseGapClosedCount(result.closed_gaps);
    } catch (e) {
      logApp.warn('[OPENCTI-MODULE] Defense coverage closed gaps not counted in the usage telemetry', { cause: e, closed_gaps: result.closed_gaps });
    }
    return result;
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Retry the level changes whose delivery failed, under the computation lock so a computation never delivers them twice.
 */
const deliverQueuedLevelChanges = async (context: AuthContext) => {
  const { changes, unreadable } = await listPendingLevelChanges();
  if (changes.length === 0 && unreadable.length === 0) return;
  let lock;
  try {
    lock = await lockResources([DEFENSE_COVERAGE_COMPUTE_KEY], { retryCount: COMPUTE_LOCK_RETRY_COUNT });
    await deliverPendingDefenseLevelChanges(context);
  } catch (e: any) {
    if (e?.name !== TYPE_LOCK_ERROR) {
      logApp.warn('[OPENCTI-MODULE] Defense coverage queued level changes delivery error, retried at the next run', { cause: e });
    }
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Nightly full computation, also triggered on request (mapping change, platform creation or deletion, manual recompute).
 */
export const defenseCoverageCronHandler = async () => {
  const context = executionContext(DEFENSE_COVERAGE_MANAGER_CONTEXT);
  try {
    await trackPendingValidationRequests(context);
  } catch (e) {
    logApp.warn('[OPENCTI-MODULE] Defense coverage queued validation tracking error, retried at the next run', { cause: e });
  }
  await deliverQueuedLevelChanges(context);
  const lastFull = await getLastFullComputation();
  const requested = await consumeFullComputationRequest();
  const isDue = !lastFull || Date.now() - new Date(lastFull).getTime() >= FULL_COMPUTATION_INTERVAL;
  if (!isDue && !requested) {
    return;
  }
  const startedAt = new Date().toISOString();
  await markFullComputationRunning(startedAt);
  try {
    await runComputation(context);
    await setLastFullComputation(startedAt);
  } catch (e) {
    // Keep the request so the next run retries
    await requestFullDefenseCoverageComputation();
    throw e;
  } finally {
    await clearFullComputationRunning();
  }
};

/**
 * Incremental computation of the techniques impacted by a batch of stream events.
 */
const handleDefenseStreamEvents = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  if (streamEvents.length === 0) return;
  const context = executionContext(DEFENSE_COVERAGE_MANAGER_CONTEXT);
  const impact = collectDefenseImpact(streamEvents);
  // Readers drop the threat overlays computed with the previous usages, or with the previous threats for filtered scopes
  if (impact.overlayChanged) await bumpDefenseOverlayVersion();
  if (impact.threatsChanged) await bumpDefenseThreatsVersion();
  if (impact.full) {
    await requestFullDefenseCoverageComputation();
    return;
  }
  const techniqueIds = new Set(impact.techniqueIds);
  const [fromDataComponents, fromRules, fromResults, fromMitigations] = await Promise.all([
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_DETECTS, Array.from(impact.dataComponentIds)),
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_INDICATES, Array.from(impact.ruleIds)),
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_HAS_COVERED, Array.from(impact.resultIds)),
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_MITIGATES, Array.from(impact.mitigationIds)),
  ]);
  fromDataComponents.forEach((id) => techniqueIds.add(id));
  fromRules.forEach((id) => techniqueIds.add(id));
  fromResults.forEach((id) => techniqueIds.add(id));
  fromMitigations.forEach((id) => techniqueIds.add(id));
  if (techniqueIds.size === 0) {
    // A new version drops the per-reader access cache built on the previous one and reloads the tactics
    if (impact.accessChanged || impact.phasesChanged) await bumpDefenseCoverageVersion();
    return;
  }
  if (techniqueIds.size > MAX_INCREMENTAL_TECHNIQUES) {
    await requestFullDefenseCoverageComputation();
    return;
  }
  try {
    await runComputation(context, Array.from(techniqueIds));
  } catch (e: any) {
    // The next full computation will catch up with these changes
    await requestFullDefenseCoverageComputation();
    if (e?.name !== TYPE_LOCK_ERROR) {
      logApp.warn('[OPENCTI-MODULE] Defense coverage incremental computation error, full computation requested', { cause: e, techniques: techniqueIds.size });
    }
  }
};

export const defenseCoverageStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>, lastEventId?: string) => {
  try {
    await handleDefenseStreamEvents(streamEvents);
  } catch (e) {
    // The next full computation catches up with the changes of this batch
    await requestFullDefenseCoverageComputation();
    logApp.warn('[OPENCTI-MODULE] Defense coverage stream batch error, full computation requested', { cause: e, events: streamEvents.length });
  }
  // Saved once the batch is handled, so a restart replays the events received while the manager was stopped
  if (lastEventId) {
    await redisSetManagerEventState(DEFENSE_COVERAGE_MANAGER_CONTEXT, lastEventId);
  }
};

export const defenseCoverageStreamStartFrom = async () => {
  return (await redisGetManagerEventState(DEFENSE_COVERAGE_MANAGER_CONTEXT)) ?? 'live';
};

const DEFENSE_COVERAGE_MANAGER_DEFINITION: ManagerDefinition = {
  id: DEFENSE_COVERAGE_MANAGER_ID,
  label: DEFENSE_COVERAGE_MANAGER_LABEL,
  executionContext: DEFENSE_COVERAGE_MANAGER_CONTEXT,
  cronSchedulerHandler: {
    handler: defenseCoverageCronHandler,
    interval: SCHEDULE_TIME,
    lockKey: DEFENSE_COVERAGE_MANAGER_KEY,
    runOnStart: true,
  },
  streamSchedulerHandler: {
    handler: defenseCoverageStreamHandler,
    interval: STREAM_SCHEDULE_TIME,
    lockKey: DEFENSE_COVERAGE_MANAGER_STREAM_KEY,
    streamOpts: { bufferTime: STREAM_BUFFER_TIME },
    streamProcessorStartFrom: defenseCoverageStreamStartFrom,
  },
  enabledByConfig: DEFENSE_COVERAGE_MANAGER_ENABLED,
  enabledToStart(): boolean {
    return this.enabledByConfig;
  },
  enabled(): boolean {
    return this.enabledByConfig;
  },
};

registerManager(DEFENSE_COVERAGE_MANAGER_DEFINITION);
