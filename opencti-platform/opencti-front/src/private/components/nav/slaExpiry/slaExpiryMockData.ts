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
    id: 'sla-mock-green',
    categoryLabel: 'CASES',
    title: '',
    ...windowWithElapsedProgress(480, 0.12),
  },
  {
    id: 'sla-mock-yellow',
    categoryLabel: 'CASES',
    title: '',
    ...windowWithElapsedProgress(360, 0.37),
  },
  {
    id: 'sla-mock-orange',
    categoryLabel: 'CASES',
    title: '',
    ...windowWithElapsedProgress(240, 0.62),
  },
  {
    id: 'sla-mock-red',
    categoryLabel: 'CASES',
    title: '',
    ...windowWithElapsedProgress(120, 0.87),
  },
  {
    id: 'sla-mock-brown',
    categoryLabel: 'CASES',
    title: '',
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
  title: '',
  startTime,
  endTime,
}));

export const fetchSlaExpiryAlerts = async (): Promise<SlaExpiryAlertItem[]> => {
  await new Promise((resolve) => {
    setTimeout(resolve, 0);
  });
  return MOCK_SLA_EXPIRY_ALERTS;
};
