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
import { findLiveScorecards, searchScorecards } from './sourceIntelligence-store';
import { maskRestrictedSources } from './sourceIntelligence-domain';

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

const assertMetric = (metric: string): keyof StoreSourceScorecard & string => {
  if (!METRIC_KEYS.has(metric as keyof StoreSourceScorecard & string)) {
    throw FunctionalError('Unknown source scorecard metric', { metric });
  }
  return metric as keyof StoreSourceScorecard & string;
};

const metricValue = (scorecard: StoreSourceScorecard, metric: string): number | null => {
  const value = (scorecard as unknown as Record<string, unknown>)[metric];
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
};

/**
 * Sources matching the widget filters (filters on the Source attributes: kind, tags, enabled...) with their live scorecard.
 * The number of sources is bounded by the source discovery settings (connectors, feeds, top authors and analysts).
 */
const loadWidgetData = async (context: AuthContext, user: AuthUser, period: ScorecardPeriodValue, filters?: FilterGroup | null) => {
  const sources = await fullEntitiesList<BasicStoreEntitySource>(context, user, [ENTITY_TYPE_SOURCE], { filters: filters ?? undefined });
  const masked = await maskRestrictedSources(context, user, sources);
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
  const data = await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters);
  const direction = args.orderMode === 'asc' ? 1 : -1;
  return data
    .map(({ source, scorecard }) => ({ label: source.name, value: metricValue(scorecard, metric), entity: source }))
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
  const data = await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters);
  const values = data.map(({ scorecard }) => metricValue(scorecard, metric)).filter((value): value is number => value !== null);
  const total = values.reduce((acc, value) => acc + value, 0);
  const aggregation = args.aggregation ?? 'sum';
  let value: number | null = null;
  if (values.length > 0) {
    if (aggregation === 'avg') value = total / values.length;
    else if (aggregation === 'max') value = Math.max(...values);
    else if (aggregation === 'min') value = Math.min(...values);
    else value = total;
  }
  return { value: value === null ? null : Math.round(value * 100) / 100, sources_count: data.length };
};

export const sourceScorecardsTimeSeries = async (
  context: AuthContext,
  user: AuthUser,
  args: { metric: string; period?: ScorecardPeriodValue | null; filters?: FilterGroup | null; startDate?: string | null; endDate?: string | null; aggregation?: string | null },
) => {
  const metric = assertMetric(args.metric);
  const data = await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters);
  const sourceIds = data.map(({ source }) => source.internal_id);
  if (sourceIds.length === 0) {
    return [];
  }
  const snapshots = await searchScorecards(context, {
    sourceIds,
    period: args.period ?? REFERENCE_SCORECARD_PERIOD,
    live: false,
    startDate: args.startDate ?? null,
    endDate: args.endDate ?? null,
    first: 1000,
    orderMode: 'asc',
  });
  const byDate = new Map<string, number[]>();
  snapshots.forEach((snapshot) => {
    const value = metricValue(snapshot, metric);
    if (value === null) return;
    const values = byDate.get(snapshot.snapshot_date) ?? [];
    values.push(value);
    byDate.set(snapshot.snapshot_date, values);
  });
  const aggregation = args.aggregation ?? 'avg';
  return Array.from(byDate.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([day, values]) => {
      const total = values.reduce((acc, value) => acc + value, 0);
      return { date: `${day}T00:00:00.000Z`, value: Math.round((aggregation === 'sum' ? total : total / values.length) * 100) / 100 };
    });
};

export const sourceScorecardsScatter = async (
  context: AuthContext,
  user: AuthUser,
  args: { xMetric: string; yMetric: string; sizeMetric?: string | null; period?: ScorecardPeriodValue | null; filters?: FilterGroup | null; first?: number | null },
) => {
  const xMetric = assertMetric(args.xMetric);
  const yMetric = assertMetric(args.yMetric);
  const sizeMetric = args.sizeMetric ? assertMetric(args.sizeMetric) : null;
  const data = await loadWidgetData(context, user, args.period ?? REFERENCE_SCORECARD_PERIOD, args.filters);
  return data
    .map(({ source, scorecard }) => ({
      entity: source,
      label: source.name,
      x: metricValue(scorecard, xMetric),
      y: metricValue(scorecard, yMetric),
      size: sizeMetric ? metricValue(scorecard, sizeMetric) : null,
    }))
    .filter((point) => point.x !== null && point.y !== null)
    .sort((a, b) => (b.size ?? 0) - (a.size ?? 0))
    .slice(0, Math.min(Math.max(args.first ?? 50, 1), 200));
};

// region Intelligence ROI dashboard template
const SOURCES_PERSPECTIVE = 'sources';

const widget = (type: string, title: string, layout: { x: number; y: number; w: number; h: number }, selection: Record<string, unknown>) => {
  const id = uuidv4();
  return {
    id,
    type,
    perspective: SOURCES_PERSPECTIVE,
    dataSelection: [{
      label: title,
      attribute: selection.attribute ?? 'value_score',
      perspective: SOURCES_PERSPECTIVE,
      filters: { mode: 'and', filters: [], filterGroups: [] },
      dynamicFrom: { mode: 'and', filters: [], filterGroups: [] },
      dynamicTo: { mode: 'and', filters: [], filterGroups: [] },
      ...selection,
    }],
    parameters: { title },
    layout: { ...layout, i: id, moved: false, static: false },
  };
};

/**
 * Built-in "Intelligence ROI" dashboard: cost vs impact, lead time ranking, noise share, top unique sources and trends.
 */
export const buildIntelligenceRoiManifest = () => {
  const widgets = [
    widget('number', 'Sources with a scorecard', { x: 0, y: 0, w: 3, h: 2 }, { attribute: 'volume_total', sort_mode: 'count' }),
    widget('number', 'Average operational value score', { x: 3, y: 0, w: 3, h: 2 }, { attribute: 'value_score', sort_mode: 'avg' }),
    widget('number', 'Average cost per actionable object', { x: 6, y: 0, w: 3, h: 2 }, { attribute: 'cost_per_actionable_object', sort_mode: 'avg' }),
    widget('number', 'Actionable objects', { x: 9, y: 0, w: 3, h: 2 }, { attribute: 'actionable_count', sort_mode: 'sum' }),
    widget('bubble', 'Cost versus impact', { x: 0, y: 2, w: 6, h: 5 }, { attribute: 'cost_per_actionable_object', field: 'impact_score', sort_by: 'volume_total' }),
    widget('horizontal-bar', 'Lead time ranking (hours)', { x: 6, y: 2, w: 6, h: 5 }, { attribute: 'lead_time_hours', sort_mode: 'desc', number: 10 }),
    widget('donut', 'Noise share', { x: 0, y: 7, w: 4, h: 5 }, { attribute: 'noise_count', sort_mode: 'desc', number: 8 }),
    widget('list', 'Top unique sources', { x: 4, y: 7, w: 4, h: 5 }, { attribute: 'unique_contribution', sort_mode: 'desc', number: 10 }),
    widget('line', 'Operational value score trend', { x: 8, y: 7, w: 4, h: 5 }, { attribute: 'value_score', sort_mode: 'avg' }),
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
