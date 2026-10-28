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
// Fields of the history and activity logs, as indexed, in the order they are offered. The backend accepts
// exactly these (HISTORY_BREAKDOWN_FIELDS in opencti-graphql/src/database/middleware.ts): keep them in sync.
// The context entity id and the free texts (messages, searches) are refused for their unbounded cardinality.
export const AUDITS_BREAKDOWN_FIELDS: { key: string; label: string }[] = [
  { key: 'event_type', label: 'Event type' },
  { key: 'event_scope', label: 'Event_scope' },
  { key: 'user_id', label: 'User' },
  { key: 'group_ids', label: 'Group' },
  { key: 'organization_ids', label: 'Organization' },
  { key: 'entity_type', label: 'Entity_type' },
  { key: 'context_data.entity_type', label: 'Type of related entity' },
];
// Fields of the logs whose values are entity types (History or Activity, the type of the related entity)
const AUDITS_TYPE_FIELDS = ['entity_type', 'context_data.entity_type'];

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
// Perspectives with a breakdown API: the schema-based ones above, and the audits with their own fields
const isBreakdownPerspective = (perspective?: WidgetPerspective | null) => {
  return perspective === 'audits' || !!getBreakdownPerspective(perspective);
};

/**
 * Fields the series are labelled with a type: an entity type, or a relationship type.
 */
export const isBreakdownTypeField = (field?: string | null) => {
  return (!!field && AUDITS_TYPE_FIELDS.includes(field)) || Object.values(BREAKDOWN_PERSPECTIVES).some((perspective) => (
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
 * Fields the first dataset of the widget can be broken down by: the fields of its entity or relationship
 * types for the entities and the relationships, the allowed fields of the logs for the audits.
 */
export const getWidgetBreakdownFieldOptions = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  widget: Pick<Widget, 'perspective' | 'dataSelection'>,
): BreakdownField[] => {
  if (widget.perspective === 'audits') {
    return AUDITS_BREAKDOWN_FIELDS;
  }
  const perspective = widget.perspective ?? 'entities';
  const types = getBreakdownEntityTypes(widget.dataSelection[0]?.filters, perspective);
  return getBreakdownFieldOptions(filterKeysSchema, types, perspective);
};

/**
 * Whether the widget breakdown field can be used on its dataset: saved or imported widgets can carry
 * a field the API refuses for the entity types of their filters, or for their perspective.
 */
export const isBreakdownFieldSupported = (
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  widget: Pick<Widget, 'perspective' | 'dataSelection' | 'parameters'>,
) => {
  return getWidgetBreakdownFieldOptions(filterKeysSchema, widget).some(({ key }) => key === widget.parameters?.breakdownBy);
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

// Audits lines and areas can count the distinct values of an attribute instead of the events
const AUDITS_DISTINCT_COUNT_TYPES = ['line', 'area'];
const isCountingDistinctValues = (widget: BreakdownWidget) => {
  return widget.perspective === 'audits'
    && AUDITS_DISTINCT_COUNT_TYPES.includes(widget.type)
    && widget.dataSelection.some((selection) => selection.unique === true);
};

// A breakdown expands the single dataset of a time series widget, counting its entities, relationships or events.
// A relationships widget can also hold entities datasets: they cannot be broken down as relationships.
const canWidgetBeBrokenDown = (widget: BreakdownWidget) => {
  const [dataset] = widget.dataSelection;
  return isBreakdownPerspective(widget.perspective)
    && getCurrentCategory(widget.type) === 'timeseries'
    && widget.dataSelection.length === 1
    && (dataset.perspective ?? widget.perspective) === widget.perspective
    && !isDraftWorkspaceFilterGroup(dataset.filters)
    && !isCountingDistinctValues(widget);
};

/**
 * Whether the breakdown can be configured: only workspace dashboards support it for now.
 */
export const isWidgetBreakdownEligible = (widget: BreakdownWidget, host?: WidgetHost) => {
  return host?.kind === 'workspace' && canWidgetBeBrokenDown(widget);
};

/**
 * Whether the breakdown controls are shown: the widget could be broken down once reduced to its
 * first dataset, counting every event. getWidgetBreakdownLockReason says why they are disabled.
 */
export const isWidgetBreakdownConfigurable = (widget: BreakdownWidget, host?: WidgetHost) => {
  const [firstSelection] = widget.dataSelection;
  return !!firstSelection && isWidgetBreakdownEligible({ ...widget, dataSelection: [{ ...firstSelection, unique: false }] }, host);
};

/**
 * Why the breakdown of a configurable widget cannot be changed: a breakdown uses a single dataset,
 * and counts every event of the logs.
 */
export const getWidgetBreakdownLockReason = (widget: BreakdownWidget): 'several-datasets' | 'distinct-values' | undefined => {
  if (widget.dataSelection.length > 1) {
    return 'several-datasets';
  }
  if (isCountingDistinctValues(widget)) {
    return 'distinct-values';
  }
  return undefined;
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
// Whatever the width, a chart draws at most this many points: past them, a wide chart with many series
// still blocks the main thread (about 0.12 ms per heatmap cell)
export const MAX_RENDERED_LINE_POINTS = 5000;
export const MAX_RENDERED_HEATMAP_CELLS = 1500;
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
  const isHeatmap = type === 'heatmap';
  const pixelsPerPoint = isHeatmap ? PIXELS_PER_HEATMAP_CELL : PIXELS_PER_LINE_POINT;
  const series = Math.max(1, seriesCount);
  const pointsPerSeries = Math.max(MIN_RENDERED_POINTS_PER_SERIES, Math.floor(chartWidth / pixelsPerPoint));
  const maxPoints = Math.max(isHeatmap ? MAX_RENDERED_HEATMAP_CELLS : MAX_RENDERED_LINE_POINTS, MIN_RENDERED_POINTS_PER_SERIES * series);
  return Math.min(pointsPerSeries * series, maxPoints);
};

type ComparableBreakdown = {
  readonly truncated: boolean;
  readonly dates: ReadonlyArray<unknown>;
  readonly series: ReadonlyArray<{
    readonly label: string;
    readonly isOther: boolean;
    readonly entity?: { readonly id?: string; readonly name?: string; readonly representative?: { readonly main: string } } | null;
    readonly values: ReadonlyArray<number>;
  }>;
};

/**
 * Whether two breakdowns draw the same chart. A refresh hands a new breakdown even when nothing changed
 * (its end date moved), and redrawing every chart of a dashboard for nothing blocks the page for seconds.
 */
export const isSameBreakdown = (a?: ComparableBreakdown | null, b?: ComparableBreakdown | null) => {
  if (a === b) return true;
  if (!a || !b || a.truncated !== b.truncated || a.dates.length !== b.dates.length || a.series.length !== b.series.length) {
    return false;
  }
  if (a.dates.some((date, index) => date !== b.dates[index])) return false;
  return a.series.every((serie, index) => {
    const other = b.series[index];
    return serie.label === other.label
      && serie.isOther === other.isOther
      && serie.entity?.id === other.entity?.id
      && serie.entity?.name === other.entity?.name
      && serie.entity?.representative?.main === other.entity?.representative?.main
      && serie.values.length === other.values.length
      && serie.values.every((value, valueIndex) => value === other.values[valueIndex]);
  });
};

// Charts measured together (a dashboard mounting its widgets) would all be drawn in one long task:
// the first one is drawn at once, the next ones one per task, so that the page responds between them
const pendingChartDraws: (() => void)[] = [];
let isChartDrawTaskBusy = false;
const drawNextChart = () => {
  const draw = pendingChartDraws.shift();
  if (draw) {
    draw();
    setTimeout(drawNextChart, 0);
  } else {
    isChartDrawTaskBusy = false;
  }
};

/**
 * Runs the first draw of a chart, at once or in a later task when another chart was just drawn.
 * Returns a function cancelling the draw if it did not run yet.
 */
export const scheduleChartDraw = (draw: () => void) => {
  if (!isChartDrawTaskBusy) {
    isChartDrawTaskBusy = true;
    draw();
    setTimeout(drawNextChart, 0);
    return () => {};
  }
  const pendingDraw = () => draw();
  pendingChartDraws.push(pendingDraw);
  return () => {
    const index = pendingChartDraws.indexOf(pendingDraw);
    if (index >= 0) pendingChartDraws.splice(index, 1);
  };
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
 * from days; starting from weeks, a week overlapping two months counts in the month of its Monday
 * (`weeksCountedByMonday`, for the warning to say so).
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
    // Months, quarters and years do not start on a Monday: each week is counted in the one of its Monday
    weeksCountedByMonday: interval === 'week' && renderedInterval !== interval,
  };
};
