import type { CaseRfiSlaApiResponse, SlaCycleMetrics } from './caseRfiSlaTypes';
import type { SlaExpiryAlertItem } from './slaExpiryTypes';

const hasCycleMetrics = (cycle?: SlaCycleMetrics | null): cycle is SlaCycleMetrics => (
  Boolean(cycle?.goalDuration?.millis)
);

const buildAlertItem = (
  result: CaseRfiSlaApiResponse['results'][number],
  slaValue: CaseRfiSlaApiResponse['results'][number]['sla_data']['values'][number],
  cycle: SlaCycleMetrics,
  cycleKey: string,
  fetchedAtMs: number,
): SlaExpiryAlertItem => ({
  id: `${result.opencti_id}-${slaValue.id}-${cycleKey}`,
  categoryLabel: slaValue.name,
  title: result.opencti_name,
  duration: {
    goalDurationMs: cycle.goalDuration.millis,
    elapsedTimeMs: cycle.elapsedTime.millis,
    remainingTimeMs: cycle.remainingTime.millis,
    fetchedAtMs,
    breached: cycle.breached ?? false,
  },
});

export const mapCaseRfiSlaResponseToAlerts = (
  response: CaseRfiSlaApiResponse,
  fetchedAtMs: number = Date.now(),
): SlaExpiryAlertItem[] => {
  const alerts: SlaExpiryAlertItem[] = [];

  for (const result of response.results) {
    for (const slaValue of result.sla_data.values) {
      if (hasCycleMetrics(slaValue.ongoingCycle)) {
        alerts.push(buildAlertItem(result, slaValue, slaValue.ongoingCycle, 'ongoing', fetchedAtMs));
      }

      for (const [index, completedCycle] of (slaValue.completedCycles ?? []).entries()) {
        if (!hasCycleMetrics(completedCycle)) {
          continue;
        }
        alerts.push(buildAlertItem(result, slaValue, completedCycle, `completed-${index}`, fetchedAtMs));
      }
    }
  }

  return alerts;
};
