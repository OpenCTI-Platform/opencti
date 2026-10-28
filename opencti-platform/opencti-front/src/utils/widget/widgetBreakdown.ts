import type { Widget, WidgetHost, WidgetParameters, WidgetPerspective } from './widget';
import { getCurrentCategory } from './widgetUtils';
import { isDraftWorkspaceFilterGroup } from '../filters/filtersUtils';
import type { FilterGroup } from '../filters/filtersHelpers-types';
import type { FilterDefinition } from '../hooks/useAuth';
import { isCustomFieldAttribute } from '../customFields';
import { daysAgo, monthsAgo } from '../Time';

export const BREAKDOWN_LIMIT_OPTIONS = [5, 10, 20, 50];
export const DEFAULT_BREAKDOWN_LIMIT = 10;

// Relation refs and id attributes with a small, stable cardinality. Vocabularies and enums are
// always allowed, whatever their key. The backend enforces the same fields, split in three
// (opencti-graphql/src/database/middleware.ts): BREAKDOWN_ALLOWED_REFS for the relation refs,
// BREAKDOWN_ALLOWED_ID_ATTRIBUTES for creator_id, and the fields of each perspective below
// (resolveBreakdownField and resolveRelationshipBreakdownField). Keep them in sync.
export const BREAKDOWN_ALLOWED_REFS = ['createdBy', 'objectLabel', 'objectMarking', 'objectAssignee', 'objectParticipant', 'creator_id'];
const BREAKDOWN_VALUE_FILTER_TYPES = ['vocabulary', 'enum'];
const isBreakdownAllowedKey = (key: string, type: string) => {
  return BREAKDOWN_ALLOWED_REFS.includes(key) || BREAKDOWN_VALUE_FILTER_TYPES.includes(type);
};
// Filter keys computed at query time, not stored on the entities: the API refuses them
const COMPUTED_FILTER_KEYS = ['computed_reliability', 'workflow_id', 'workflowInstanceCurrentState', 'connectedToId', 'ids', 'id'];
// Only set inside drafts, where breakdowns are not available: every value would be empty
const DRAFT_FILTER_KEYS = ['draft_change.draft_operation'];

type BreakdownField = { key: string; label: string };
interface BreakdownPerspective {
  // Filter key restricting the types of the dataset
  typeFilterKey: string;
  // Types of the dataset without such a filter
  defaultTypes: string[];
  // The type itself, offered when the dataset is not restricted to a single type
  typeField: BreakdownField;
  // Fields of the perspective that are not read from the schema
  fields: BreakdownField[];
}
const BREAKDOWN_PERSPECTIVES: Partial<Record<WidgetPerspective, BreakdownPerspective>> = {
  entities: {
    typeFilterKey: 'entity_type',
    defaultTypes: ['Stix-Core-Object'],
    typeField: { key: 'entity_type', label: 'Entity type' },
    fields: [],
  },
  relationships: {
    typeFilterKey: 'relationship_type',
    // Every relationship, as the relationships time series without relationship type
    defaultTypes: ['stix-relationship'],
    typeField: { key: 'relationship_type', label: 'Relationship type' },
    // Each relationship has a single source and a single target, among a bounded number of types
    fields: [{ key: 'fromTypes', label: 'Source type' }, { key: 'toTypes', label: 'Target type' }],
  },
};
const getBreakdownPerspective = (perspective?: WidgetPerspective | null) => {
  return perspective ? BREAKDOWN_PERSPECTIVES[perspective] : undefined;
};

/**
 * Fields the series are labelled with a type: an entity type, or a relationship type.
 */
export const isBreakdownTypeField = (field?: string | null) => {
  return Object.values(BREAKDOWN_PERSPECTIVES).some((perspective) => (
    perspective.typeField.key === field || perspective.fields.some(({ key }) => key === field)
  ));
};

/**
 * The breakdown field is a filter key: a value is set when a field is chosen.
 */
export const isBreakdownField = (value?: string | null): value is string => {
  return !!value;
};

/**
 * Types every element of the dataset belongs to, read from a top level "entity type = ..." filter,
 * or "relationship type = ..." for relationships. Empty when the filters do not restrict the type for sure.
 */
export const getBreakdownEntityTypes = (filters?: FilterGroup | null, perspective: WidgetPerspective = 'entities'): string[] => {
  const typeFilterKey = getBreakdownPerspective(perspective)?.typeFilterKey;
  if (!filters || !typeFilterKey) return [];
  const isRestrictingGroup = filters.mode === 'and' || filters.filters.length + filters.filterGroups.length === 1;
  const typeFilter = filters.filters.find((filter) => filter.key === typeFilterKey);
  if (!isRestrictingGroup || !typeFilter || (typeFilter.operator && typeFilter.operator !== 'eq') || typeFilter.mode === 'and') {
    return [];
  }
  return typeFilter.values.filter((value): value is string => typeof value === 'string');
};

/**
 * Fields the dataset can be broken down by: with a single type, its allowed fields
 * (BREAKDOWN_ALLOWED_REFS, vocabularies and enums); with several types, the ones they have in common,
 * plus the type itself. Relationships can also be broken down by the type of their source or target.
 */
export const getBreakdownFieldOptions = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  entityTypes: string[],
  perspective: WidgetPerspective = 'entities',
): BreakdownField[] => {
  const breakdownPerspective = getBreakdownPerspective(perspective);
  if (!breakdownPerspective) return [];
  const types = entityTypes.length > 0 ? entityTypes : breakdownPerspective.defaultTypes;
  const schemas = types.map((type) => filterKeysSchema.get(type) ?? new Map<string, FilterDefinition>());
  const options: BreakdownField[] = [];
  schemas[0].forEach((definition, key) => {
    // Abstract types also list the keys of some of their sub types: keep the keys of the type itself
    const isCommon = types.every((type, index) => schemas[index].get(key)?.subEntityTypes.includes(type));
    // Custom fields are not stored as attributes: the API cannot break them down
    const isStored = !COMPUTED_FILTER_KEYS.includes(key) && !DRAFT_FILTER_KEYS.includes(key) && !isCustomFieldAttribute(key);
    if (isCommon && isBreakdownAllowedKey(key, definition.type) && isStored) {
      options.push({ key, label: definition.label });
    }
  });
  options.push(...breakdownPerspective.fields);
  if (entityTypes.length !== 1) {
    options.push(breakdownPerspective.typeField);
  }
  return options.sort((a, b) => a.label.localeCompare(b.label));
};

/**
 * Whether the widget breakdown field can be used on its dataset: saved or imported widgets can carry
 * a field the API refuses for the entity types of their filters.
 */
export const isBreakdownFieldSupported = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  widget: Pick<Widget, 'dataSelection' | 'parameters' | 'perspective'>,
) => {
  const perspective = widget.perspective ?? 'entities';
  const entityTypes = getBreakdownEntityTypes(widget.dataSelection[0]?.filters, perspective);
  return getBreakdownFieldOptions(filterKeysSchema, entityTypes, perspective).some(({ key }) => key === widget.parameters?.breakdownBy);
};

export const getWidgetBreakdownLimit = (parameters?: WidgetParameters | null) => {
  return parameters?.breakdownLimit ?? DEFAULT_BREAKDOWN_LIMIT;
};

export const getWidgetBreakdownOrder = (parameters?: WidgetParameters | null): 'asc' | 'desc' => {
  return parameters?.breakdownOrder === 'asc' ? 'asc' : 'desc';
};

export const getWidgetBreakdownOther = (parameters?: WidgetParameters | null) => {
  return parameters?.breakdownOther ?? false;
};

/**
 * Start date used when the dashboard sets none: a daily breakdown over the default 12 months
 * would draw too many bars, so it only looks back 30 days.
 */
export const getBreakdownDefaultStartDate = (interval: string) => {
  return interval === 'day' ? daysAgo(30) : monthsAgo(12);
};

type BreakdownWidget = Pick<Widget, 'type' | 'perspective' | 'dataSelection'>;

// A breakdown expands the single dataset of a time series widget, of entities or of relationships.
// A relationships widget can also hold entities datasets: they cannot be broken down as relationships.
const canWidgetBeBrokenDown = (widget: BreakdownWidget) => {
  const [dataset] = widget.dataSelection;
  return !!getBreakdownPerspective(widget.perspective)
    && getCurrentCategory(widget.type) === 'timeseries'
    && widget.dataSelection.length === 1
    && (dataset.perspective ?? widget.perspective) === widget.perspective
    && !isDraftWorkspaceFilterGroup(dataset.filters);
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
// revealed again for each bar drawn), so bar charts are kept under these sizes. The bar budget follows
// the width of the chart: bars thinner than PIXELS_PER_BAR add cost without adding readable detail.
export const MIN_RENDERED_BARS = 150;
export const MAX_RENDERED_BARS = 600;
export const PIXELS_PER_BAR = 2;
// Lines, areas and heatmaps draw every series across the whole width: a point closer than
// PIXELS_PER_LINE_POINT to the next one, or a heatmap cell thinner than PIXELS_PER_HEATMAP_CELL,
// adds cost (SVG nodes, path length, hover lookups) without adding readable detail
export const PIXELS_PER_LINE_POINT = 2;
export const PIXELS_PER_HEATMAP_CELL = 6;
const MIN_RENDERED_POINTS_PER_SERIES = 10;
export const PIXELS_PER_X_LABEL = 60;
// Animating more points than this blocks the main thread for seconds, whatever the chart type
export const ANIMATION_POINTS_THRESHOLD = 300;
// Relative change under which a new chart width is ignored, to not redraw the chart on small resizes
const CHART_WIDTH_HYSTERESIS = 0.2;

/**
 * Number of bars the chart can draw for a given width in pixels, an unknown width gives the maximum.
 */
export const getRenderedBarsBudget = (width: number) => {
  if (!(width > 0)) return MAX_RENDERED_BARS;
  return Math.min(MAX_RENDERED_BARS, Math.max(MIN_RENDERED_BARS, Math.floor(width / PIXELS_PER_BAR)));
};

/**
 * Number of points the chart can draw for a given width in pixels: bars share the width between
 * every series, while lines, areas and heatmaps draw each series across the whole width.
 */
export const getRenderedPointsBudget = (type: string, width: number, seriesCount: number) => {
  if (type === 'vertical-bar') return getRenderedBarsBudget(width);
  const chartWidth = width > 0 ? width : MAX_RENDERED_BARS * PIXELS_PER_BAR;
  const pixelsPerPoint = type === 'heatmap' ? PIXELS_PER_HEATMAP_CELL : PIXELS_PER_LINE_POINT;
  const pointsPerSeries = Math.max(MIN_RENDERED_POINTS_PER_SERIES, Math.floor(chartWidth / pixelsPerPoint));
  return pointsPerSeries * Math.max(1, seriesCount);
};

/**
 * Width the chart is laid out for after a resize: the previous one is kept until the new one differs
 * by 20 % or more, so that the bars budget and the x axis labels do not change on every pixel.
 */
export const nextBreakdownChartWidth = (previous: number | undefined, width: number) => {
  if (previous === undefined || !(previous > 0)) return width;
  return Math.abs(width - previous) < previous * CHART_WIDTH_HYSTERESIS ? previous : width;
};

/**
 * Number of labels of the x axis for a given width in pixels.
 */
export const getBreakdownTickAmount = (width: number) => {
  return Math.max(2, Math.floor(width / PIXELS_PER_X_LABEL));
};

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
 * Sums the series into coarser intervals until the chart draws at most `maxPoints` points.
 * Buckets are always rebuilt from the original points, so counts stay exact when starting
 * from days; starting from weeks, a week overlapping two months counts in the month of its Monday.
 */
export const coarsenSeriesForRendering = <T extends { data: TimeSeriesPoint[] }>(
  series: T[],
  interval: string,
  maxPoints = MAX_RENDERED_BARS,
) => {
  const countPoints = (candidate: T[]) => candidate.reduce((count, serie) => count + serie.data.length, 0);
  let renderedInterval = interval;
  let renderedSeries = series;
  while (countPoints(renderedSeries) > maxPoints && COARSER_INTERVAL[renderedInterval]) {
    const coarserInterval = COARSER_INTERVAL[renderedInterval];
    renderedInterval = coarserInterval;
    renderedSeries = series.map((serie) => ({ ...serie, data: sumByInterval(serie.data, coarserInterval) }));
  }
  return {
    series: renderedSeries,
    interval: renderedInterval,
    pointsCount: countPoints(renderedSeries),
  };
};
