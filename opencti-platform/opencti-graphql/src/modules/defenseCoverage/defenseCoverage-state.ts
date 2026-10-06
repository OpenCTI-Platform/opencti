import {
  redisDeleteDefensePendingLevelChanges,
  redisDeleteDefensePendingValidationTracking,
  redisGetDefensePendingLevelChanges,
  redisGetDefensePendingValidationTrackings,
  redisGetManagerEventState,
  redisGetSetManagerEventState,
  redisSetDefensePendingLevelChanges,
  redisSetDefensePendingValidationTracking,
  redisSetManagerEventState,
} from '../../database/redis';
import { now } from '../../utils/format';
import type { DefenseGapValidationRequest } from './defenseGap/defenseGap-types';
import type { DefenseValidationTarget } from './defenseCoverage-utils';
import type { DefenseCoverageChange } from './defenseCoverage-notification';

// Cluster-wide state of the defense coverage computation, shared through Redis between the API nodes.
const STATE_VERSION = 'DEFENSE_COVERAGE_VERSION';
const STATE_OVERLAY_VERSION = 'DEFENSE_OVERLAY_VERSION';
const STATE_THREATS_VERSION = 'DEFENSE_THREATS_VERSION';
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

/**
 * Version of the threats themselves. Bumped when a threat or one of its relationships changes, so the overlays of
 * filtered scopes, whose threats are the ones matching the filters, are recomputed with the current matches.
 */
export const getDefenseThreatsVersion = async (): Promise<string> => {
  return (await redisGetManagerEventState(STATE_THREATS_VERSION)) ?? 'none';
};

export const bumpDefenseThreatsVersion = async () => {
  const version = now();
  await redisSetManagerEventState(STATE_THREATS_VERSION, version);
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

/**
 * Read and reset the request in one step, so a request made while it is consumed stays pending for the next run.
 */
export const consumeFullComputationRequest = async (): Promise<boolean> => {
  return (await redisGetSetManagerEventState(STATE_FULL_REQUESTED, 'false')) === 'true';
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
 * Start date of the full computation in progress, null when none is. Bounded in time so a node stopped mid-run never leaves it running forever.
 */
export const getFullComputationRunningSince = async (): Promise<string | null> => {
  const since = await redisGetManagerEventState(STATE_FULL_RUNNING_SINCE);
  if (!since) return null;
  const elapsed = Date.now() - new Date(since).getTime();
  return Number.isFinite(elapsed) && elapsed < FULL_RUNNING_MAX_DURATION ? since : null;
};

export const isFullComputationRunning = async (): Promise<boolean> => {
  return (await getFullComputationRunningSince()) !== null;
};

/**
 * A created validation request whose tracking on its gaps failed, kept until the manager tracks it.
 */
export interface DefensePendingValidationTracking {
  request: DefenseGapValidationRequest;
  targets: DefenseValidationTarget[];
}

export const queuePendingValidationTracking = async (pending: DefensePendingValidationTracking) => {
  await redisSetDefensePendingValidationTracking(pending.request.security_coverage_id, JSON.stringify(pending));
};

/**
 * Queued trackings by Security Coverage id; an entry that cannot be read has no `pending` so the caller drops it.
 */
export const listPendingValidationTrackings = async (): Promise<Array<{ id: string; pending?: DefensePendingValidationTracking }>> => {
  const entries = await redisGetDefensePendingValidationTrackings();
  return Object.entries(entries ?? {}).map(([id, value]) => {
    try {
      const pending = JSON.parse(value) as DefensePendingValidationTracking;
      const readable = pending?.request?.security_coverage_id === id && Array.isArray(pending.targets);
      return readable ? { id, pending } : { id };
    } catch {
      return { id };
    }
  });
};

export const clearPendingValidationTracking = async (securityCoverageId: string) => {
  await redisDeleteDefensePendingValidationTracking(securityCoverageId);
};

const parsePendingChange = (value: string | undefined): DefenseCoverageChange | undefined => {
  try {
    const change = value ? JSON.parse(value) : undefined;
    return change?.attack_pattern_id && change.previous && change.coverage ? change as DefenseCoverageChange : undefined;
  } catch {
    return undefined;
  }
};

/**
 * Queue level changes for their delivery to the live triggers, before the new coverage is stored: the stored coverage
 * becomes their baseline, so a later computation would never find them again. One entry per technique: a change queued
 * again for a technique (a computation retried after a failure, or a new change before the delivery) keeps the first
 * previous coverage and the latest coverage, and is delivered again to every trigger.
 */
export const queuePendingLevelChanges = async (changes: DefenseCoverageChange[]) => {
  if (changes.length === 0) return;
  const queued = await redisGetDefensePendingLevelChanges(changes.map((change) => change.attack_pattern_id));
  const entries: Record<string, string> = {};
  changes.forEach((change) => {
    const earlier = parsePendingChange(queued[change.attack_pattern_id]);
    const merged: DefenseCoverageChange = { attack_pattern_id: change.attack_pattern_id, previous: earlier?.previous ?? change.previous, coverage: change.coverage };
    entries[change.attack_pattern_id] = JSON.stringify(merged);
  });
  await redisSetDefensePendingLevelChanges(entries);
};

/**
 * Queued changes, and the ids of the entries that cannot be read (the caller drops them).
 */
export const listPendingLevelChanges = async (): Promise<{ changes: DefenseCoverageChange[]; unreadable: string[] }> => {
  const entries = await redisGetDefensePendingLevelChanges();
  const changes: DefenseCoverageChange[] = [];
  const unreadable: string[] = [];
  Object.entries(entries ?? {}).forEach(([id, value]) => {
    const change = parsePendingChange(value);
    if (change) changes.push(change);
    else unreadable.push(id);
  });
  return { changes, unreadable };
};

export const savePendingLevelChange = async (change: DefenseCoverageChange) => {
  await redisSetDefensePendingLevelChanges({ [change.attack_pattern_id]: JSON.stringify(change) });
};

export const clearPendingLevelChanges = async (attackPatternIds: string[]) => {
  await redisDeleteDefensePendingLevelChanges(attackPatternIds);
};
