import { redisGetManagerEventState, redisSetManagerEventState } from '../../database/redis';
import { now } from '../../utils/format';

// Cluster-wide state of the defense coverage computation, shared through Redis between the API nodes.
const STATE_VERSION = 'DEFENSE_COVERAGE_VERSION';
const STATE_FULL_RUN = 'DEFENSE_COVERAGE_FULL_RUN';
const STATE_FULL_REQUESTED = 'DEFENSE_COVERAGE_FULL_REQUESTED';

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
