import { redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { now } from '../../utils/format';

// Cluster-wide state of the defense coverage computation, shared through Redis between the API nodes.
const STATE_VERSION = 'DEFENSE_COVERAGE_VERSION';
const STATE_OVERLAY_VERSION = 'DEFENSE_OVERLAY_VERSION';
const STATE_FULL_RUN = 'DEFENSE_COVERAGE_FULL_RUN';
const STATE_FULL_REQUESTED = 'DEFENSE_COVERAGE_FULL_REQUESTED';
const STATE_FULL_RUNNING_SINCE = 'DEFENSE_COVERAGE_FULL_RUNNING_SINCE';
const FULL_RUNNING_MAX_DURATION = 2 * 60 * 60 * 1000;

/**
 * Version of the stored coverage. Bumped after every write so readers drop their caches.
 */
export const getDefenseCoverageVersion = async (): Promise<string> => {
  return (await redisGetManagerEventState(STATE_VERSION)) ?? 'none';
};

export const bumpDefenseCoverageVersion = async () => {
  const version = now();
  await redisSetManagerEventState(STATE_VERSION, version);
  return version;
};

/**
 * Version of the threat usages behind the overlays. Bumped when a `uses` relationship or the access to a threat
 * changes, so readers drop the overlays they computed with the previous usages.
 */
export const getDefenseOverlayVersion = async (): Promise<string> => {
  return (await redisGetManagerEventState(STATE_OVERLAY_VERSION)) ?? 'none';
};

export const bumpDefenseOverlayVersion = async () => {
  const version = now();
  await redisSetManagerEventState(STATE_OVERLAY_VERSION, version);
  return version;
};

export const getLastFullComputation = async (): Promise<string | null> => {
  return redisGetManagerEventState(STATE_FULL_RUN);
};

export const setLastFullComputation = async (date: string) => {
  await redisSetManagerEventState(STATE_FULL_RUN, date);
};

/**
 * Ask the manager for a full recomputation at its next run (mapping change, platform deletion, manual request).
 */
export const requestFullDefenseCoverageComputation = async () => {
  await redisSetManagerEventState(STATE_FULL_REQUESTED, 'true');
};

export const consumeFullComputationRequest = async (): Promise<boolean> => {
  const requested = await redisGetManagerEventState(STATE_FULL_REQUESTED);
  if (requested === 'true') {
    await redisSetManagerEventState(STATE_FULL_REQUESTED, 'false');
    return true;
  }
  return false;
};

export const isFullComputationRequested = async (): Promise<boolean> => {
  return (await redisGetManagerEventState(STATE_FULL_REQUESTED)) === 'true';
};

export const markFullComputationRunning = async (startedAt: string) => {
  await redisSetManagerEventState(STATE_FULL_RUNNING_SINCE, startedAt);
};

export const clearFullComputationRunning = async () => {
  await redisSetManagerEventState(STATE_FULL_RUNNING_SINCE, '');
};

/**
 * Whether a full computation is in progress. Bounded in time so a node stopped mid-run never leaves it running forever.
 */
export const isFullComputationRunning = async (): Promise<boolean> => {
  const since = await redisGetManagerEventState(STATE_FULL_RUNNING_SINCE);
  if (!since) return false;
  const elapsed = Date.now() - new Date(since).getTime();
  return Number.isFinite(elapsed) && elapsed < FULL_RUNNING_MAX_DURATION;
};
