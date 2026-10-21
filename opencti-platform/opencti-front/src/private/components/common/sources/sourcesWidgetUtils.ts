import type { DashboardConfig } from '../../../../components/dashboard/dashboard-types';
import { computeStartEndDates } from '../../../../components/dashboard/dashboardVizUtils';
import {
  findSourceWidgetMetric,
  REFERENCE_SCORECARD_PERIOD,
  SCORECARD_PERIOD_DAYS,
  SOURCE_WIDGET_METRICS,
  ScorecardPeriod,
  type SourceWidgetMetric,
} from '../../integrations/sources/sourceIntelligenceUtils';

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

export const periodDaysFromDashboardConfig = (config: DashboardConfig): number => SCORECARD_PERIOD_DAYS[periodFromDashboardConfig(config)];

// Empty widgets say why they are empty
export const NO_SOURCE_SCORED_MESSAGE = 'No source scored in this period';

type Translate = (message: string, options?: { values?: Record<string, string | number> }) => string;

/**
 * Axis title of a metric with its unit: ratios are plotted as percents, scores range from 0 to 100 and costs are in the
 * currency the widget aggregated; durations carry their unit in their label.
 */
export const metricAxisTitle = (t: Translate, metric: Pick<SourceWidgetMetric, 'label' | 'type'>, currency?: string | null): string => {
  const measure = t(metric.label);
  if (metric.type === 'ratio') return t('{measure} (%)', { values: { measure } });
  if (metric.type === 'score') return t('{measure} (0 to 100)', { values: { measure } });
  if (metric.type === 'cost' && currency) return t('{measure} ({currency})', { values: { measure, currency } });
  return measure;
};

export type SourcesAggregation = 'avg' | 'sum' | 'min' | 'max';

export const toAggregation = (value: string | null | undefined, fallback: SourcesAggregation): SourcesAggregation => {
  return value === 'avg' || value === 'sum' || value === 'min' || value === 'max' ? value : fallback;
};

// `count` counts the scored sources instead of aggregating the metric
export const SOURCES_NUMBER_COUNT_MODE = 'count';

/**
 * Metric a number widget queries. A count reads no metric: it queries a Community Edition one, so a widget saved with an
 * Enterprise Edition metric keeps counting after a downgrade.
 */
export const numberWidgetMetricKey = (selection: { attribute?: string | null; sort_mode?: string | null }): string => {
  if (selection.sort_mode === SOURCES_NUMBER_COUNT_MODE) {
    return (SOURCE_WIDGET_METRICS.find((metric) => !metric.enterprise) ?? SOURCE_WIDGET_METRICS[0]).key;
  }
  return findSourceWidgetMetric(selection.attribute).key;
};
