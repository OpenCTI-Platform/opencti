export type ScorecardPeriod = 'LAST_7_DAYS' | 'LAST_30_DAYS' | 'LAST_90_DAYS';

export const SCORECARD_PERIODS: ScorecardPeriod[] = ['LAST_7_DAYS', 'LAST_30_DAYS', 'LAST_90_DAYS'];
export const REFERENCE_SCORECARD_PERIOD: ScorecardPeriod = 'LAST_30_DAYS';

export const SCORECARD_PERIOD_LABELS: Record<ScorecardPeriod, string> = {
  LAST_7_DAYS: 'Last 7 days',
  LAST_30_DAYS: 'Last 30 days',
  LAST_90_DAYS: 'Last 90 days',
};

export const SCORECARD_PERIOD_DAYS: Record<ScorecardPeriod, number> = {
  LAST_7_DAYS: 7,
  LAST_30_DAYS: 30,
  LAST_90_DAYS: 90,
};

export const SOURCE_KIND_LABELS: Record<string, string> = {
  connector: 'Connector',
  ingestion_feed: 'Ingestion feed',
  author: 'Author',
  manual: 'Analyst',
};

// Settings of the computation, weights, thresholds, tuning, autonomy and gaps, under Settings > Customization
export const SOURCE_INTELLIGENCE_SETTINGS_PATH = '/dashboard/settings/customization/source_intelligence';

// Provenance assertion kinds and the source kind scoring them, as the backend joins them (inference and emulation are not sources)
export const ASSERTION_KIND_TO_SOURCE_KIND: Record<string, string> = {
  connector: 'connector',
  feed: 'ingestion_feed',
  author: 'author',
  user: 'manual',
};

/**
 * Scorecard page of a provenance source, through a route that finds the source of the assertion and redirects to it.
 * The source internal id is unknown where assertions are displayed.
 */
export const sourceScorecardRefLink = (source: { readonly source_kind: string; readonly source_id: string }): string | null => {
  if (!ASSERTION_KIND_TO_SOURCE_KIND[source.source_kind] || !source.source_id) {
    return null;
  }
  return `/dashboard/integrations/sources/source/ref/${source.source_kind}/${encodeURIComponent(source.source_id)}`;
};

export const RECOMMENDATION_KIND_LABELS: Record<string, string> = {
  raise_confidence: 'Raise confidence',
  lower_confidence: 'Lower confidence',
  add_decay_rule: 'Add decay rule',
  change_schedule: 'Change schedule',
  add_deny_list: 'Add deny list',
  quarantine: 'Quarantine to draft',
  retire: 'Retire source',
  add_connector: 'Add connector',
};

export const RECOMMENDATION_STATUS_LABELS: Record<string, string> = {
  proposed: 'Proposed',
  applied: 'Applied',
  dismissed: 'Dismissed',
  reverted: 'Reverted',
  failed: 'Failed',
};

export const COST_PERIOD_LABELS: Record<string, string> = {
  month: 'Per month',
  quarter: 'Per quarter',
  year: 'Per year',
};

export type ScorecardMetricType = 'count' | 'ratio' | 'hours' | 'cost' | 'score';

export interface SourceWidgetMetric {
  key: string;
  label: string;
  type: ScorecardMetricType;
  enterprise: boolean;
}

// Scorecard metrics of the "Intelligence sources" dashboard perspective (same keys as the sourceScorecard* API metrics)
export const SOURCE_WIDGET_METRICS: SourceWidgetMetric[] = [
  { key: 'value_score', label: 'Operational value score', type: 'score', enterprise: false },
  { key: 'volume_total', label: 'Volume', type: 'count', enterprise: false },
  { key: 'new_objects', label: 'New objects', type: 'count', enterprise: false },
  { key: 'volume_indicators', label: 'Indicators', type: 'count', enterprise: false },
  { key: 'unique_count', label: 'Unique objects', type: 'count', enterprise: false },
  { key: 'unique_contribution', label: 'Unique contribution', type: 'ratio', enterprise: false },
  { key: 'corroboration_rate', label: 'Corroboration rate', type: 'ratio', enterprise: false },
  { key: 'lead_time_hours', label: 'Lead time (hours)', type: 'hours', enterprise: false },
  { key: 'first_reporter_share', label: 'First reporter share', type: 'ratio', enterprise: false },
  { key: 'accuracy', label: 'Accuracy', type: 'ratio', enterprise: false },
  { key: 'relevance', label: 'Relevance', type: 'ratio', enterprise: true },
  { key: 'impact_score', label: 'Impact score', type: 'score', enterprise: false },
  { key: 'sightings_count', label: 'Sightings', type: 'count', enterprise: false },
  { key: 'security_platform_sightings_count', label: 'Security platform sightings', type: 'count', enterprise: false },
  { key: 'incidents_count', label: 'Incidents referencing', type: 'count', enterprise: false },
  { key: 'noise', label: 'Noise', type: 'ratio', enterprise: false },
  { key: 'noise_count', label: 'Noisy objects', type: 'count', enterprise: false },
  { key: 'freshness_hours', label: 'Freshness (hours)', type: 'hours', enterprise: false },
  { key: 'actionable_count', label: 'Actionable objects', type: 'count', enterprise: false },
  { key: 'cost_per_actionable_object', label: 'Cost per actionable object', type: 'cost', enterprise: false },
  { key: 'community_uniqueness', label: 'Community uniqueness', type: 'ratio', enterprise: false },
];

export const findSourceWidgetMetric = (key: string | null | undefined): SourceWidgetMetric => {
  return SOURCE_WIDGET_METRICS.find((metric) => metric.key === key) ?? SOURCE_WIDGET_METRICS[0];
};

// Widgets plot ratios as percents
export const toWidgetValue = (value: number | null | undefined, type: ScorecardMetricType): number | null => {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  return type === 'ratio' ? Math.round(value * 1000) / 10 : value;
};

export const SOURCE_WIDGET_AGGREGATIONS = ['avg', 'sum', 'min', 'max'] as const;

const isNumber = (value: number | null | undefined): value is number => typeof value === 'number' && Number.isFinite(value);

export const formatRatio = (value: number | null | undefined, digits = 1): string => {
  if (!isNumber(value)) return '-';
  return `${(value * 100).toFixed(digits)} %`;
};

export const formatScore = (value: number | null | undefined): string => {
  if (!isNumber(value)) return '-';
  return `${Math.round(value)}`;
};

// Durations below two days stay in hours, longer ones are shown in days; the sign carries the lead / lag meaning
export const formatHours = (value: number | null | undefined): string => {
  if (!isNumber(value)) return '-';
  const absolute = Math.abs(value);
  const sign = value < 0 ? '-' : '';
  if (absolute < 48) {
    return `${sign}${absolute.toFixed(1)} h`;
  }
  return `${sign}${(absolute / 24).toFixed(1)} d`;
};

export const formatCount = (value: number | null | undefined): string => {
  if (!isNumber(value)) return '-';
  if (Math.abs(value) >= 1000000) return `${(value / 1000000).toFixed(1)}M`;
  if (Math.abs(value) >= 1000) return `${(value / 1000).toFixed(1)}K`;
  return `${Math.round(value)}`;
};

export const formatCost = (value: number | null | undefined, currency?: string | null): string => {
  if (!isNumber(value)) return '-';
  const amount = value >= 100 ? value.toFixed(0) : value.toFixed(value >= 1 ? 2 : 4);
  return currency ? `${amount} ${currency}` : amount;
};

export const formatMetric = (value: number | null | undefined, type: ScorecardMetricType, currency?: string | null): string => {
  switch (type) {
    case 'ratio':
      return formatRatio(value);
    case 'hours':
      return formatHours(value);
    case 'cost':
      return formatCost(value, currency);
    case 'score':
      return formatScore(value);
    default:
      return formatCount(value);
  }
};

export type ScoreLevel = 'good' | 'average' | 'poor' | 'unknown';

// Level of a value on a 0-1 (ratio) or 0-100 (score) scale, inverted for metrics where lower is better (noise)
export const scoreLevel = (value: number | null | undefined, options: { scale?: 1 | 100; higherIsBetter?: boolean } = {}): ScoreLevel => {
  if (!isNumber(value)) return 'unknown';
  const scale = options.scale ?? 1;
  const normalized = Math.min(1, Math.max(0, value / scale));
  const oriented = options.higherIsBetter === false ? 1 - normalized : normalized;
  if (oriented >= 0.66) return 'good';
  if (oriented >= 0.33) return 'average';
  return 'poor';
};

const HTML_ESCAPES: Record<string, string> = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

// Chart tooltips are raw HTML: names coming from connectors, feeds or authors must never be interpreted
export const escapeHtml = (value: unknown): string => String(value ?? '').replace(/[&<>"']/g, (char) => HTML_ESCAPES[char]);

export const parseJsonObject = (value: string | null | undefined): Record<string, unknown> => {
  if (!value) return {};
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
};

export interface OverlapCell {
  source_a: string;
  source_b: string;
  shared_count: number;
  share_a: number;
  share_b: number;
  jaccard: number;
}

export interface OverlapSource {
  id: string;
  name: string;
}

export interface OverlapHeatmapPoint {
  x: string;
  y: number | null;
  sharedCount: number;
}

export interface OverlapHeatmapSerie {
  name: string;
  data: OverlapHeatmapPoint[];
}

/**
 * Heatmap series of the overlap matrix: one row per source, one column per source, the value of the cell (row, column)
 * is the share of the row source objects also asserted by the column source (asymmetric).
 * The diagonal is left empty; rows come out in reverse order because the heatmap draws the first serie at the bottom.
 */
export const buildOverlapHeatmapSeries = (sources: readonly OverlapSource[], cells: readonly OverlapCell[]): OverlapHeatmapSerie[] => {
  const byPair = new Map<string, { share: number; shared: number }>();
  cells.forEach((cell) => {
    byPair.set(`${cell.source_a}|${cell.source_b}`, { share: cell.share_a, shared: cell.shared_count });
    byPair.set(`${cell.source_b}|${cell.source_a}`, { share: cell.share_b, shared: cell.shared_count });
  });
  return sources.map((row) => ({
    name: row.name,
    data: sources.map((column) => {
      if (row.id === column.id) {
        return { x: column.name, y: null, sharedCount: 0 };
      }
      const pair = byPair.get(`${row.id}|${column.id}`);
      return { x: column.name, y: pair ? Math.round(pair.share * 1000) / 10 : 0, sharedCount: pair?.shared ?? 0 };
    }),
  })).reverse();
};

export interface ScorecardTrendPoint {
  snapshot_date: string;
  is_live: boolean;
  [metric: string]: unknown;
}

/**
 * Time serie of one scorecard metric from the daily snapshots, the live scorecard (if any) is the last point.
 * Ratios are converted to percents so the chart axis reads naturally.
 */
export const buildTrendSerie = (scorecards: readonly ScorecardTrendPoint[], metric: string, type: ScorecardMetricType) => {
  const points = new Map<string, number>();
  [...scorecards]
    .sort((a, b) => a.snapshot_date.localeCompare(b.snapshot_date) || Number(a.is_live) - Number(b.is_live))
    .forEach((scorecard) => {
      const value = scorecard[metric];
      if (typeof value === 'number' && Number.isFinite(value)) {
        points.set(scorecard.snapshot_date, type === 'ratio' ? Math.round(value * 1000) / 10 : value);
      }
    });
  return Array.from(points.entries()).map(([date, value]) => ({ x: `${date}T00:00:00.000Z`, y: value }));
};

export const periodStartDate = (period: ScorecardPeriod, now = Date.now()) => {
  return new Date(now - SCORECARD_PERIOD_DAYS[period] * 24 * 3600 * 1000).toISOString();
};
