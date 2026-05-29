import type { SlaExpiryAlertItem } from './slaExpiryTypes';

const windowWithElapsedProgress = (
  totalMinutes: number,
  elapsedFraction: number,
): { startTime: string; endTime: string } => {
  const totalMs = totalMinutes * 60 * 1000;
  const elapsedMs = totalMs * Math.min(Math.max(elapsedFraction, 0), 1);
  const startMs = Date.now() - elapsedMs;
  const endMs = startMs + totalMs;
  return {
    startTime: new Date(startMs).toISOString(),
    endTime: new Date(endMs).toISOString(),
  };
};

/**
 * Sample data until the SLA expiry API is available.
 * Replace `fetchSlaExpiryAlerts` in useSlaExpiryAlerts with the real endpoint.
 */
export const MOCK_SLA_EXPIRY_ALERTS: SlaExpiryAlertItem[] = [
  {
    id: 'sla-mock-1',
    categoryLabel: 'CASES',
    title: 'SLA Expiring Soon',
    ...windowWithElapsedProgress(120, 0.82),
  },
  {
    id: 'sla-mock-2',
    categoryLabel: 'CASES',
    title: 'SLA Expiring Soon',
    ...windowWithElapsedProgress(240, 0.4),
  },
  {
    id: 'sla-mock-3',
    categoryLabel: 'CASES',
    title: 'SLA Expiring Soon',
    startTime: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString(),
    endTime: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  },
];

/** Map API windows `[start, end]` into alert items once the endpoint is ready. */
export const mapSlaExpiryApiWindows = (
  windows: ReadonlyArray<readonly [string, string]>,
): SlaExpiryAlertItem[] => windows.map(([startTime, endTime], index) => ({
  id: `sla-${index}-${endTime}`,
  categoryLabel: 'CASES',
  title: 'SLA Expiring Soon',
  startTime,
  endTime,
}));

export const fetchSlaExpiryAlerts = async (): Promise<SlaExpiryAlertItem[]> => {
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
  return MOCK_SLA_EXPIRY_ALERTS;
};
