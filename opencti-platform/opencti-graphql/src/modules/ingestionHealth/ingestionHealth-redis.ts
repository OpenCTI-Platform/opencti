import { getClientBase } from '../../database/redis';
import type { HeartbeatObservation } from './ingestionHealth-types';

// The ingestion health manager memory between two cycles (RFC 0001 §4.4).
// No TTL on purpose: it must outlive a dead connector. It is removed with the connector.
const observationKey = (sourceId: string) => `ingestion-health-observation:${sourceId}`;

export const redisGetIngestionHealthObservation = async (sourceId: string): Promise<HeartbeatObservation | null> => {
  const rawObservation = await getClientBase().get(observationKey(sourceId));
  if (!rawObservation) {
    return null;
  }
  try {
    return JSON.parse(rawObservation) as HeartbeatObservation;
  } catch {
    return null;
  }
};

export const redisSetIngestionHealthObservation = async (sourceId: string, observation: HeartbeatObservation) => {
  await getClientBase().set(observationKey(sourceId), JSON.stringify(observation));
};

export const redisDeleteIngestionHealthObservation = async (sourceId: string) => {
  await getClientBase().del(observationKey(sourceId));
};

// Start time of the manager's last full cycle (a pass that listed every connector), one key for the platform.
// It tells the manager whether
// it was blind for a while (restart, lost lock), so a wide gap between two pings is not blamed
// on the connector. It also answers « is the ingestion health manager alive » for an operator.
const LAST_RUN_KEY = 'ingestion-health-manager-last-run';

export const redisGetIngestionHealthLastRun = async (): Promise<Date | null> => {
  const rawDate = await getClientBase().get(LAST_RUN_KEY);
  const date = rawDate ? new Date(rawDate) : null;
  return date && !Number.isNaN(date.getTime()) ? date : null;
};

export const redisSetIngestionHealthLastRun = async (at: Date) => {
  await getClientBase().set(LAST_RUN_KEY, at.toISOString());
};
