import { v4 as uuidv4 } from 'uuid';
import type { AuthContext, AuthUser } from '../../types/user';
import { createEntity } from '../../database/middleware';
import { fullEntitiesList } from '../../database/middleware-loader';
import { notify } from '../../database/redis';
import { BUS_TOPICS } from '../../config/conf';
import { FunctionalError } from '../../config/errors';
import { publishUserAction } from '../../listener/UserActionListener';
import { MEMBER_ACCESS_RIGHT_ADMIN } from '../../utils/access';
import { ENTITY_TYPE_WORKSPACE } from '../workspace/workspace-types';
import type { FilterGroup } from '../../generated/graphql';
import { addSourceIntelligenceDashboardCount } from '../../manager/telemetryManager';
import { type BasicStoreEntitySource, ENTITY_TYPE_SOURCE, REFERENCE_SCORECARD_PERIOD, type ScorecardPeriodValue, type StoreSourceScorecard } from './sourceIntelligence-types';
import { aggregateScorecardSnapshotsByDay, findLiveScorecards, type ScorecardAggregation } from './sourceIntelligence-store';
import { maskRestrictedSources, restrictSourceQueryToEdition } from './sourceIntelligence-domain';
import { isEnterpriseEdition } from '../../enterprise-edition/ee';

export type ScorecardMetricType = 'count' | 'ratio' | 'hours' | 'cost' | 'score';

export interface ScorecardMetric {
  key: keyof StoreSourceScorecard & string;
  label: string;
  type: ScorecardMetricType;
  higher_is_better: boolean;
  enterprise: boolean;
}

// Scorecard attributes exposed to the dashboard widgets of the Sources perspective
export const SCORECARD_METRICS: ScorecardMetric[] = [
  { key: 'value_score', label: 'Operational value score', type: 'score', higher_is_better: true, enterprise: false },
  { key: 'volume_total', label: 'Volume', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'new_objects', label: 'New objects', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'volume_indicators', label: 'Indicators', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'unique_count', label: 'Unique objects', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'unique_contribution', label: 'Unique contribution', type: 'ratio', higher_is_better: true, enterprise: false },
  { key: 'corroboration_rate', label: 'Corroboration rate', type: 'ratio', higher_is_better: true, enterprise: false },
  { key: 'lead_time_hours', label: 'Lead time (hours)', type: 'hours', higher_is_better: true, enterprise: false },
  { key: 'first_reporter_share', label: 'First reporter share', type: 'ratio', higher_is_better: true, enterprise: false },
  { key: 'accuracy', label: 'Accuracy', type: 'ratio', higher_is_better: true, enterprise: false },
  { key: 'relevance', label: 'Relevance', type: 'ratio', higher_is_better: true, enterprise: true },
  { key: 'impact_score', label: 'Impact score', type: 'score', higher_is_better: true, enterprise: false },
  { key: 'sightings_count', label: 'Sightings', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'security_platform_sightings_count', label: 'Security platform sightings', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'incidents_count', label: 'Incidents referencing', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'noise', label: 'Noise', type: 'ratio', higher_is_better: false, enterprise: false },
  { key: 'noise_count', label: 'Noisy objects', type: 'count', higher_is_better: false, enterprise: false },
  { key: 'freshness_hours', label: 'Freshness (hours)', type: 'hours', higher_is_better: false, enterprise: false },
  { key: 'actionable_count', label: 'Actionable objects', type: 'count', higher_is_better: true, enterprise: false },
  { key: 'cost_per_actionable_object', label: 'Cost per actionable object', type: 'cost', higher_is_better: false, enterprise: false },
  { key: 'community_uniqueness', label: 'Community uniqueness', type: 'ratio', higher_is_better: true, enterprise: false },
];

const METRIC_KEYS = new Set(SCORECARD_METRICS.map((metric) => metric.key));
const ENTERPRISE_METRIC_KEYS = new Set<string>(SCORECARD_METRICS.filter((metric) => metric.enterprise).map((metric) => metric.key));

const assertMetric = (metric: string): keyof StoreSourceScorecard & string => {
  if (!METRIC_KEYS.has(metric as keyof StoreSourceScorecard & string)) {
    throw FunctionalError('Unknown source scorecard metric', { metric });
  }
  return metric as keyof StoreSourceScorecard & string;
};

// Scorecards keep the Enterprise Edition metrics computed before a license downgrade: they are served in Enterprise Edition only
const assertMetricsAllowed = async (context: AuthContext, metrics: Array<string | null>) => {
  const enterpriseMetrics = metrics.filter((metric): metric is string => metric !== null && ENTERPRISE_METRIC_KEYS.has(metric));
  if (enterpriseMetrics.length > 0 && !(await isEnterpriseEdition(context))) {
    throw FunctionalError('This source scorecard metric requires an Enterprise Edition license', { metrics: enterpriseMetrics });
  }
};

const metricValue = (scorecard: StoreSourceScorecard, metric: string): number | null => {
  const value = (scorecard as unknown as Record<string, unknown>)[metric];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
};

const AGGREGATIONS: readonly ScorecardAggregation[] = ['sum', 'avg', 'min', 'max'];

const assertAggregation = (aggregation: string | null | undefined, fallback: ScorecardAggregation): ScorecardAggregation => {
  if (!aggregation) {
    return fallback;
  }
  if (!(AGGREGATIONS as readonly string[]).includes(aggregation)) {
    throw FunctionalError('Unknown source scorecard aggregation', { aggregation });
  }
  return aggregation as ScorecardAggregation;
};

export const aggregateValues = (values: number[], aggregation: ScorecardAggregation): number | null => {
  if (values.length === 0) {
    return null;
  }
  switch (aggregation) {
    case 'avg':
      return values.reduce((acc, value) => acc + value, 0) / values.length;
    case 'min':
      return Math.min(...values);
    case 'max':
      return Math.max(...values);
    case 'sum':
      return values.reduce((acc, value) => acc + value, 0);
    default:
      throw FunctionalError('Unknown source scorecard aggregation', { aggregation });
  }
};

const COST_METRIC_KEYS = new Set<string>(SCORECARD_METRICS.filter((metric) => metric.type === 'cost').map((metric) => metric.key));

type WidgetEntry = { source: BasicStoreEntitySource; scorecard: StoreSourceScorecard };

/**
 * Costs are manual inputs in the currency of each source and are never converted: an aggregation over a cost metric
 * only uses the currency declared by most of the selected sources (alphabetical order on a tie), the others are left out.
 * Returns null when no selected source has a cost.
 */
export const dominantCostCurrency = (scorecards: Array<Pick<StoreSourceScorecard, 'cost_currency'>>): string | null => {
  const counts = new Map<string, number>();
  scorecards.forEach(({ cost_currency }) => {
    if (cost_currency) counts.set(cost_currency, (counts.get(cost_currency) ?? 0) + 1);
  });
  const ranked = [...counts.entries()].sort(([a, countA], [b, countB]) => countB - countA || a.localeCompare(b));
  return ranked.length > 0 ? ranked[0][0] : null;
};

const restrictToCostCurrency = (data: WidgetEntry[], metrics: Array<string | null>): { data: WidgetEntry[]; currency: string | null } => {
  if (!metrics.some((metric) => metric !== null && COST_METRIC_KEYS.has(metric))) {
    return { data, currency: null };
  }
  const currency = dominantCostCurrency(data.map(({ scorecard }) => scorecard));
  return { data: currency ? data.filter(({ scorecard }) => scorecard.cost_currency === currency) : [], currency };
};

/**
 * Sources matching the widget filters (filters on the Source attributes: kind, tags, enabled...), live scorecard or not.
 * The number of sources is bounded by the source discovery settings (connectors, feeds, top authors and analysts).
 */
const loadWidgetSources = async (context: AuthContext, user: AuthUser, filters?: FilterGroup | null) => {
  const allowed = await restrictSourceQueryToEdition(context, { filters });
  const sources = await fullEntitiesList<BasicStoreEntitySource>(context, user, [ENTITY_TYPE_SOURCE], { filters: allowed.filters ?? undefined });
  return maskRestrictedSources(context, user, sources);
};

/** Sources matching the widget filters with their live scorecard: a source without one (disabled) is left out. */
const loadWidgetData = async (context: AuthContext, user: AuthUser, period: ScorecardPeriodValue, filters?: FilterGroup | null) => {
  const masked = await loadWidgetSources(context, user, filters);
  const scorecards = await findLiveScorecards(context, period, masked.map((source) => source.internal_id));
  const bySource = new Map(scorecards.map((scorecard) => [scorecard.source_id, scorecard]));
  return masked
    .map((source) => ({ source, scorecard: bySource.get(source.internal_id) }))
    .filter((entry): entry is { source: BasicStoreEntitySource; scorecard: StoreSourceScorecard } => entry.scorecard !== undefined);
};

export const sourceScorecardsDistribution = async (
  context: AuthContext,
  user: AuthUser,
  args: { metric: string; period?: ScorecardPeriodValue | null; filters?: FilterGroup | null; first?: number | null; orderMode?: string | null },
) => {
  const metric = assertMetric(args.metric);
  await assertMetricsAllowed(context, [metric]);
  const { data, currency } = restrictToCostCurrency(await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters), [metric]);
  const direction = args.orderMode === 'asc' ? 1 : -1;
  return data
    .map(({ source, scorecard }) => ({ label: source.name, value: metricValue(scorecard, metric), currency, entity: source }))
    .filter((item) => item.value !== null)
    .sort((a, b) => direction * ((a.value as number) - (b.value as number)) || a.label.localeCompare(b.label))
    .slice(0, Math.min(Math.max(args.first ?? 10, 1), 100));
};

export const sourceScorecardsNumber = async (
  context: AuthContext,
  user: AuthUser,
  args: { metric: string; period?: ScorecardPeriodValue | null; filters?: FilterGroup | null; aggregation?: string | null },
) => {
  const metric = assertMetric(args.metric);
  await assertMetricsAllowed(context, [metric]);
  const loaded = await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters);
  const { data, currency } = restrictToCostCurrency(loaded, [metric]);
  const values = data.map(({ scorecard }) => metricValue(scorecard, metric)).filter((value): value is number => value !== null);
  const value = aggregateValues(values, assertAggregation(args.aggregation, 'sum'));
  // The number of sources counts every scored source, whatever the currency of its cost
  return { value: value === null ? null : Math.round(value * 100) / 100, sources_count: loaded.length, currency };
};

export const sourceScorecardsTimeSeries = async (
  context: AuthContext,
  user: AuthUser,
  args: { metric: string; period?: ScorecardPeriodValue | null; filters?: FilterGroup | null; startDate?: string | null; endDate?: string | null; aggregation?: string | null },
) => {
  const metric = assertMetric(args.metric);
  await assertMetricsAllowed(context, [metric]);
  const period = args.period ?? REFERENCE_SCORECARD_PERIOD;
  // The history of a source outlives its live scorecards (a disabled source has none): every matching source counts
  const sources = await loadWidgetSources(context, user, args.filters);
  const sourceIds = sources.map((source) => source.internal_id);
  let currency: string | null = null;
  if (COST_METRIC_KEYS.has(metric)) {
    // The currency each source has in the other widgets, its declared cost when it has no live scorecard
    const liveCurrencies = new Map((await findLiveScorecards(context, period, sourceIds)).map((scorecard) => [scorecard.source_id, scorecard.cost_currency]));
    currency = dominantCostCurrency(sources.map((source) => ({
      cost_currency: liveCurrencies.has(source.internal_id) ? liveCurrencies.get(source.internal_id) ?? null : source.source_cost?.currency ?? null,
    })));
    if (!currency) {
      return [];
    }
  }
  const points = await aggregateScorecardSnapshotsByDay(context, {
    sourceIds,
    period,
    metric,
    costCurrency: currency,
    aggregation: assertAggregation(args.aggregation, 'avg'),
    startDate: args.startDate ?? null,
    endDate: args.endDate ?? null,
  });
  return points.map(({ day, value }) => ({ date: `${day}T00:00:00.000Z`, value: Math.round(value * 100) / 100, currency }));
};

export const sourceScorecardsScatter = async (
  context: AuthContext,
  user: AuthUser,
  args: { xMetric: string; yMetric: string; sizeMetric?: string | null; period?: ScorecardPeriodValue | null; filters?: FilterGroup | null; first?: number | null },
) => {
  const xMetric = assertMetric(args.xMetric);
  const yMetric = assertMetric(args.yMetric);
  const sizeMetric = args.sizeMetric ? assertMetric(args.sizeMetric) : null;
  await assertMetricsAllowed(context, [xMetric, yMetric, sizeMetric]);
  const loaded = await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters);
  const { data, currency } = restrictToCostCurrency(loaded, [xMetric, yMetric, sizeMetric]);
  return data
    .map(({ source, scorecard }) => ({
      entity: source,
      label: source.name,
      x: metricValue(scorecard, xMetric),
      y: metricValue(scorecard, yMetric),
      size: sizeMetric ? metricValue(scorecard, sizeMetric) : null,
      currency,
    }))
    // An unmeasured value is never drawn as a zero: the point is left out
    .filter((point) => point.x !== null && point.y !== null && (sizeMetric === null || point.size !== null))
    .sort((a, b) => (b.size ?? 0) - (a.size ?? 0))
    .slice(0, Math.min(Math.max(args.first ?? 50, 1), 200));
};

// region Intelligence ROI dashboard template
const SOURCES_PERSPECTIVE = 'sources';

// No stored title: each widget names its measure, aggregation and scorecard period in the reader's language, and
// follows the time range of the dashboard
const widget = (type: string, layout: { x: number; y: number; w: number; h: number }, selection: Record<string, unknown>) => {
  const id = uuidv4();
  return {
    id,
    type,
    perspective: SOURCES_PERSPECTIVE,
    dataSelection: [{
      attribute: selection.attribute ?? 'value_score',
      perspective: SOURCES_PERSPECTIVE,
      filters: { mode: 'and', filters: [], filterGroups: [] },
      dynamicFrom: { mode: 'and', filters: [], filterGroups: [] },
      dynamicTo: { mode: 'and', filters: [], filterGroups: [] },
      ...selection,
    }],
    parameters: {},
    layout: { ...layout, i: id, moved: false, static: false },
  };
};

/**
 * Built-in "Intelligence ROI" dashboard: cost vs impact, lead time ranking, noise share, top unique sources and trends.
 */
export const buildIntelligenceRoiManifest = () => {
  const widgets = [
    widget('number', { x: 0, y: 0, w: 3, h: 2 }, { attribute: 'volume_total', sort_mode: 'count' }),
    widget('number', { x: 3, y: 0, w: 3, h: 2 }, { attribute: 'value_score', sort_mode: 'avg' }),
    widget('number', { x: 6, y: 0, w: 3, h: 2 }, { attribute: 'cost_per_actionable_object', sort_mode: 'avg' }),
    widget('number', { x: 9, y: 0, w: 3, h: 2 }, { attribute: 'actionable_count', sort_mode: 'sum' }),
    widget('bubble', { x: 0, y: 2, w: 6, h: 5 }, { attribute: 'cost_per_actionable_object', field: 'impact_score', sort_by: 'volume_total' }),
    widget('horizontal-bar', { x: 6, y: 2, w: 6, h: 5 }, { attribute: 'lead_time_hours', sort_mode: 'desc', number: 10 }),
    widget('donut', { x: 0, y: 7, w: 4, h: 5 }, { attribute: 'noise_count', sort_mode: 'desc', number: 8 }),
    widget('list', { x: 4, y: 7, w: 4, h: 5 }, { attribute: 'unique_contribution', sort_mode: 'desc', number: 10 }),
    widget('line', { x: 8, y: 7, w: 4, h: 5 }, { attribute: 'value_score', sort_mode: 'avg' }),
  ];
  const manifest = {
    widgets: Object.fromEntries(widgets.map((w) => [w.id, w])),
    config: { relativeDate: 'months-3' },
  };
  return Buffer.from(JSON.stringify(manifest), 'utf-8').toString('base64');
};

export const createIntelligenceRoiDashboard = async (context: AuthContext, user: AuthUser, name?: string | null) => {
  const dashboardName = (name ?? '').trim() || 'Intelligence ROI';
  if (dashboardName.length < 2 || dashboardName.length > 250) {
    throw FunctionalError('Invalid dashboard name');
  }
  const input = {
    type: 'dashboard',
    name: dashboardName,
    description: 'Built-in Source Intelligence dashboard: operational value, cost, lead time, noise and uniqueness of every source.',
    manifest: buildIntelligenceRoiManifest(),
    restricted_members: [{ id: user.id, access_right: MEMBER_ACCESS_RIGHT_ADMIN }],
  };
  const created = await createEntity(context, user, input, ENTITY_TYPE_WORKSPACE);
  await publishUserAction({
    user,
    event_type: 'mutation',
    event_scope: 'create',
    event_access: 'extended',
    message: `creates dashboard workspace \`${dashboardName}\` from the Intelligence ROI template`,
    context_data: { id: created.id, entity_type: ENTITY_TYPE_WORKSPACE, input: { name: dashboardName, template: 'intelligence-roi' } },
  });
  await addSourceIntelligenceDashboardCount();
  return notify(BUS_TOPICS[ENTITY_TYPE_WORKSPACE].ADDED_TOPIC, created, user);
};
// endregion
