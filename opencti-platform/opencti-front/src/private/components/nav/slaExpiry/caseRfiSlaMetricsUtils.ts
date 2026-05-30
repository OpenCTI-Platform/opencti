import type { CaseRfiSlaApiResponse, SlaCycleMetrics, SlaValueItem } from './caseRfiSlaTypes';

export interface CaseRfiSlaRemainingTimeSnapshot {
  goalDurationMs: number;
  elapsedTimeMs: number;
  remainingTimeMs: number;
  fetchedAtMs: number;
  breached?: boolean;
}

export const hasCycleMetrics = (cycle?: SlaCycleMetrics | null): cycle is SlaCycleMetrics => (
  Boolean(cycle?.goalDuration?.millis)
);

const getMetricsFromSlaValue = (slaValue: SlaValueItem): SlaCycleMetrics | null => {
  if (hasCycleMetrics(slaValue.ongoingCycle)) {
    return slaValue.ongoingCycle;
  }

  const completedCycles = slaValue.completedCycles ?? [];
  for (let index = completedCycles.length - 1; index >= 0; index -= 1) {
    const cycle = completedCycles[index];
    if (hasCycleMetrics(cycle)) {
      return cycle;
    }
  }

  return null;
};

const isTotalSlaValueName = (name: string): boolean => (
  name.toLowerCase().includes('total')
);

export const getTotalSlaValueMetrics = (
  values: SlaValueItem[],
): SlaCycleMetrics | null => {
  for (let index = values.length - 1; index >= 0; index -= 1) {
    const slaValue = values[index];
    if (!isTotalSlaValueName(slaValue.name)) {
      continue;
    }

    const metrics = getMetricsFromSlaValue(slaValue);
    if (metrics) {
      return metrics;
    }
  }

  return null;
};

export const mapCaseRfiSlaResponseToRemainingById = (
  response: CaseRfiSlaApiResponse,
  requestedOpenctiIds: string[] = [],
  fetchedAtMs: number = Date.now(),
): Record<string, CaseRfiSlaRemainingTimeSnapshot> => {
  const remainingById: Record<string, CaseRfiSlaRemainingTimeSnapshot> = {};
  const snapshots: CaseRfiSlaRemainingTimeSnapshot[] = [];

  for (const result of response.results) {
    const metrics = getTotalSlaValueMetrics(result.sla_data.values);
    if (!metrics) {
      continue;
    }

    const snapshot: CaseRfiSlaRemainingTimeSnapshot = {
      goalDurationMs: metrics.goalDuration.millis,
      elapsedTimeMs: metrics.elapsedTime.millis,
      remainingTimeMs: metrics.remainingTime.millis,
      fetchedAtMs,
      breached: metrics.breached ?? false,
    };

    snapshots.push(snapshot);
    remainingById[result.opencti_id] = snapshot;
  }

  if (requestedOpenctiIds.length === 0 || snapshots.length === 0) {
    return remainingById;
  }

  requestedOpenctiIds.forEach((openctiId, index) => {
    if (remainingById[openctiId]) {
      return;
    }
    remainingById[openctiId] = snapshots[index % snapshots.length];
  });

  return remainingById;
};

export const getCaseRfiSlaMetricsAt = (
  snapshot: CaseRfiSlaRemainingTimeSnapshot,
  nowMs: number = Date.now(),
) => {
  const deltaMs = nowMs - snapshot.fetchedAtMs;
  return {
    goalDurationMs: snapshot.goalDurationMs,
    elapsedTimeMs: snapshot.elapsedTimeMs + deltaMs,
    remainingTimeMs: snapshot.remainingTimeMs - deltaMs,
  };
};

export const getCaseRfiSlaProgress = (
  snapshot: CaseRfiSlaRemainingTimeSnapshot,
  nowMs: number = Date.now(),
): number => {
  const { goalDurationMs, elapsedTimeMs } = getCaseRfiSlaMetricsAt(snapshot, nowMs);
  if (goalDurationMs <= 0) {
    return 0;
  }
  return Math.min(1, Math.max(0, elapsedTimeMs / goalDurationMs));
};

export const formatCaseRfiSlaDurationDisplay = (durationMs: number): string => {
  const totalSeconds = Math.floor(Math.abs(durationMs) / 1000);
  const days = Math.floor(totalSeconds / 86400);
  const hours = Math.floor((totalSeconds % 86400) / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  return [days, hours, minutes, seconds]
    .map((unit) => String(unit).padStart(2, '0'))
    .join(':');
};
