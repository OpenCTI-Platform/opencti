import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import { REFERENCE_SCORECARD_PERIOD, ScorecardPeriod } from '../../integrations/sources/sourceIntelligenceUtils';

const DAY_MS = 24 * 3600 * 1000;

/**
 * Scorecards are precomputed over rolling 7, 30 and 90 day windows: the dashboard time range picks the window
 * that covers it (the 30 day reference window when the dashboard has no time range).
 */
export const periodFromRange = (startDate: string | null | undefined, endDate: string | null | undefined, now = Date.now()): ScorecardPeriod => {
  if (!startDate) {
    return REFERENCE_SCORECARD_PERIOD;
  }
  const start = new Date(startDate).getTime();
  const end = endDate ? new Date(endDate).getTime() : now;
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) {
    return REFERENCE_SCORECARD_PERIOD;
  }
  const days = (end - start) / DAY_MS;
  if (days <= 7.5) return 'LAST_7_DAYS';
  if (days <= 31) return 'LAST_30_DAYS';
  return 'LAST_90_DAYS';
};

export const periodFromDashboardConfig = (config: DashboardConfig): ScorecardPeriod => {
  const { startDate, endDate } = computeStartEndDates(config);
  return periodFromRange(startDate, endDate);
};

export type SourcesAggregation = 'avg' | 'sum' | 'min' | 'max';

export const toAggregation = (value: string | null | undefined, fallback: SourcesAggregation): SourcesAggregation => {
  return value === 'avg' || value === 'sum' || value === 'min' || value === 'max' ? value : fallback;
};
