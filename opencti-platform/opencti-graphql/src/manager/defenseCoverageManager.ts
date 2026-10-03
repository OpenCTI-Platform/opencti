import { type ManagerDefinition, registerManager } from './managerModule';
import conf, { booleanConf, logApp } from '../config/conf';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { lockResources } from '../lock/master-lock';
import { TYPE_LOCK_ERROR } from '../config/errors';
import type { DataEvent, SseEvent } from '../types/event';
import { RELATION_DETECTS, RELATION_INDICATES } from '../schema/stixCoreRelationship';
import { computeDefenseCoverage, findTechniquesOfSources } from '../modules/defenseCoverage/defenseCoverage-compute';
import { collectDefenseImpact } from '../modules/defenseCoverage/defenseCoverage-impact';
import {
  bumpDefenseCoverageVersion,
  bumpDefenseOverlayVersion,
  clearFullComputationRunning,
  consumeFullComputationRequest,
  getLastFullComputation,
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
    await addDefenseGapClosedCount(result.closed_gaps);
    return result;
  } finally {
    if (lock) await lock.unlock();
  }
};

/**
 * Nightly full computation, also triggered on request (mapping change, platform creation or deletion, manual recompute).
 */
export const defenseCoverageCronHandler = async () => {
  const context = executionContext(DEFENSE_COVERAGE_MANAGER_CONTEXT);
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
export const defenseCoverageStreamHandler = async (streamEvents: Array<SseEvent<DataEvent>>) => {
  if (streamEvents.length === 0) return;
  const context = executionContext(DEFENSE_COVERAGE_MANAGER_CONTEXT);
  const impact = collectDefenseImpact(streamEvents);
  // Readers drop the threat overlays computed with the previous usages
  if (impact.overlayChanged) await bumpDefenseOverlayVersion();
  if (impact.full) {
    await requestFullDefenseCoverageComputation();
    return;
  }
  const techniqueIds = new Set(impact.techniqueIds);
  const [fromDataComponents, fromRules] = await Promise.all([
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_DETECTS, Array.from(impact.dataComponentIds)),
    findTechniquesOfSources(context, SYSTEM_USER, RELATION_INDICATES, Array.from(impact.ruleIds)),
  ]);
  fromDataComponents.forEach((id) => techniqueIds.add(id));
  fromRules.forEach((id) => techniqueIds.add(id));
  if (techniqueIds.size === 0) {
    // A new version drops the per-reader access cache built on the previous one
    if (impact.accessChanged) await bumpDefenseCoverageVersion();
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
      logApp.error('[OPENCTI-MODULE] Defense coverage incremental computation error', { cause: e, techniques: techniqueIds.size });
    }
  }
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
    streamProcessorStartFrom: () => 'live',
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
