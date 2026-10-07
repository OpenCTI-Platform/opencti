import type { Widget, WidgetHost, WidgetParameters } from './widget';
import { getCurrentCategory } from './widgetUtils';
import { isDraftWorkspaceFilterGroup } from '../filters/filtersUtils';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { FilterDefinition } from '../hooks/useAuth';

export const BREAKDOWN_LIMIT_OPTIONS = [5, 10, 20, 50];
export const DEFAULT_BREAKDOWN_LIMIT = 10;

const ENTITY_TYPE_FIELD = 'entity_type';
const DEFAULT_ENTITY_TYPE = 'Stix-Core-Object';
// Relation refs and id attributes (authors, labels, markings, assignees, creators, statuses...),
// vocabularies and enums: values with a small, stable cardinality
const BREAKDOWN_FILTER_TYPES = ['id', 'vocabulary', 'enum'];
// Filter keys computed at query time, not stored on the entities: the API refuses them
const COMPUTED_FILTER_KEYS = ['computed_reliability', 'workflow_id', 'workflowInstanceCurrentState', 'connectedToId', 'ids', 'id'];
// Only set inside drafts, where breakdowns are not available: every value would be empty
const DRAFT_FILTER_KEYS = ['draft_change.draft_operation'];

/**
 * The breakdown field is a filter key: a value is set when a field is chosen.
 */
export const isBreakdownField = (value?: string | null): value is string => {
  return !!value;
};

/**
 * Entity types every entity of the dataset belongs to, read from a top level "entity type = ..." filter.
 * Empty when the filters do not restrict the type for sure.
 */
export const getBreakdownEntityTypes = (filters?: FilterGroup | null): string[] => {
  if (!filters) return [];
  const isRestrictingGroup = filters.mode === 'and' || filters.filters.length + filters.filterGroups.length === 1;
  const typeFilter = filters.filters.find((filter) => filter.key === ENTITY_TYPE_FIELD);
  if (!isRestrictingGroup || !typeFilter || (typeFilter.operator && typeFilter.operator !== 'eq') || typeFilter.mode === 'and') {
    return [];
  }
  return typeFilter.values.filter((value): value is string => typeof value === 'string');
};

/**
 * Fields the dataset can be broken down by: with a single entity type, any of its fields;
 * with several types, the fields they have in common, plus the entity type itself.
 */
export const getBreakdownFieldOptions = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  entityTypes: string[],
): { key: string; label: string }[] => {
  const types = entityTypes.length > 0 ? entityTypes : [DEFAULT_ENTITY_TYPE];
  const schemas = types.map((type) => filterKeysSchema.get(type) ?? new Map<string, FilterDefinition>());
  const options: { key: string; label: string }[] = [];
  schemas[0].forEach((definition, key) => {
    // Abstract types also list the keys of some of their sub types: keep the keys of the type itself
    const isCommon = types.every((type, index) => schemas[index].get(key)?.subEntityTypes.includes(type));
    if (isCommon && BREAKDOWN_FILTER_TYPES.includes(definition.type) && !COMPUTED_FILTER_KEYS.includes(key) && !DRAFT_FILTER_KEYS.includes(key)) {
      options.push({ key, label: definition.label });
    }
  });
  if (entityTypes.length !== 1) {
    options.push({ key: ENTITY_TYPE_FIELD, label: 'Entity type' });
  }
  return options.sort((a, b) => a.label.localeCompare(b.label));
};

export const getWidgetBreakdownLimit = (parameters?: WidgetParameters | null) => {
  return parameters?.breakdownLimit ?? DEFAULT_BREAKDOWN_LIMIT;
};

type BreakdownWidget = Pick<Widget, 'type' | 'perspective' | 'dataSelection'>;

// A breakdown expands the single entities dataset of a time series widget
const canWidgetBeBrokenDown = (widget: BreakdownWidget) => {
  return widget.perspective === 'entities'
    && getCurrentCategory(widget.type) === 'timeseries'
    && widget.dataSelection.length === 1
    && !isDraftWorkspaceFilterGroup(widget.dataSelection[0].filters);
};

/**
 * Whether the breakdown can be configured: only workspace dashboards support it for now.
 */
export const isWidgetBreakdownEligible = (widget: BreakdownWidget, host?: WidgetHost) => {
  return host?.kind === 'workspace' && canWidgetBeBrokenDown(widget);
};

/**
 * Whether the widget is configured with a breakdown, whatever renders it.
 */
export const hasWidgetBreakdown = (widget: Widget) => {
  return isBreakdownField(widget.parameters?.breakdownBy) && canWidgetBeBrokenDown(widget);
};

/**
 * Whether the widget must be rendered as a breakdown.
 */
export const isWidgetBreakdownActive = (widget: Widget, host?: WidgetHost) => {
  return host?.kind === 'workspace' && hasWidgetBreakdown(widget);
};

// ApexCharts bar rendering cost grows with the square of the number of bars (every bar is
// revealed again for each bar drawn), so bar charts are kept under these sizes.
export const MAX_RENDERED_BARS = 1200;
export const ANIMATION_BAR_THRESHOLD = 300;

const COARSER_INTERVAL: Record<string, string> = {
  day: 'week',
  week: 'month',
  month: 'quarter',
  quarter: 'year',
};

// Start of the UTC calendar bucket, matching the backend date histogram (weeks start on Monday)
const getBucketStart = (date: Date, interval: string) => {
  const year = date.getUTCFullYear();
  const month = date.getUTCMonth();
  switch (interval) {
    case 'week': {
      const daysSinceMonday = (date.getUTCDay() + 6) % 7;
      return Date.UTC(year, month, date.getUTCDate() - daysSinceMonday);
    }
    case 'month':
      return Date.UTC(year, month, 1);
    case 'quarter':
      return Date.UTC(year, month - (month % 3), 1);
    case 'year':
      return Date.UTC(year, 0, 1);
    default:
      return Date.UTC(year, month, date.getUTCDate());
  }
};

type TimeSeriesPoint = { x: Date; y: number };

const sumByInterval = (data: TimeSeriesPoint[], interval: string): TimeSeriesPoint[] => {
  const sums = new Map<number, number>();
  data.forEach(({ x, y }) => {
    const bucketStart = getBucketStart(x, interval);
    sums.set(bucketStart, (sums.get(bucketStart) ?? 0) + y);
  });
  return Array.from(sums, ([bucketStart, y]) => ({ x: new Date(bucketStart), y }));
};

/**
 * Sums the series into coarser intervals until the chart draws at most `maxBars` bars.
 * Buckets are always rebuilt from the original points, so counts stay exact when starting
 * from days; starting from weeks, a week overlapping two months counts in the month of its Monday.
 */
export const coarsenSeriesForRendering = <T extends { data: TimeSeriesPoint[] }>(
  series: T[],
  interval: string,
  maxBars = MAX_RENDERED_BARS,
) => {
  const countBars = (candidate: T[]) => candidate.reduce((count, serie) => count + serie.data.length, 0);
  let renderedInterval = interval;
  let renderedSeries = series;
  while (countBars(renderedSeries) > maxBars && COARSER_INTERVAL[renderedInterval]) {
    const coarserInterval = COARSER_INTERVAL[renderedInterval];
    renderedInterval = coarserInterval;
    renderedSeries = series.map((serie) => ({ ...serie, data: sumByInterval(serie.data, coarserInterval) }));
  }
  return {
    series: renderedSeries,
    interval: renderedInterval,
    barsCount: countBars(renderedSeries),
  };
};
