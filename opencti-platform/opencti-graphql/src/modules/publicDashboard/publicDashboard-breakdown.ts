import moment, { type DurationInputArg2, type unitOfTime } from 'moment';
import type { GraphQLError } from 'graphql';
import { FUNCTIONAL_ERROR, FunctionalError, UnsupportedError } from '../../config/errors';
import { TIME_SERIES_BREAKDOWN_DEFAULT_LIMIT } from '../../database/middleware';
import { countTimeSeriesIntervals } from '../../database/utils';
import { type FilterGroup, FilterMode, FilterOperator, type QueryPublicStixCoreObjectsTimeSeriesBreakdownArgs } from '../../generated/graphql';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_OBJECT, RELATION_OBJECT_LABEL } from '../../schema/stixRefRelationship';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { RELATION_TYPE_FILTER, TYPE_FILTER } from '../../utils/filtering/filtering-constants';
import type { PublicDashboardCachedWidget } from './publicDashboard-types';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../draftWorkspace/draftWorkspace-types';

// Perspectives with a public breakdown API: the logs of the audits widgets have none
type PublicBreakdownPerspective = 'entities' | 'relationships';
type PublicBreakdownRequest = Pick<QueryPublicStixCoreObjectsTimeSeriesBreakdownArgs, 'widgetId' | 'startDate' | 'endDate'>;
type PublicBreakdownWidget = Pick<PublicDashboardCachedWidget, 'type' | 'perspective' | 'dataSelection' | 'parameters'>;

// Widgets drawing a time series, the only ones a breakdown expands (the 'timeseries' category of the front widgets)
const TIME_SERIES_WIDGET_TYPES = ['vertical-bar', 'line', 'area', 'heatmap'];
// Perspectives whose widgets can be broken down, the audits ones included (isBreakdownPerspective in the front)
const BREAKDOWN_PERSPECTIVES = ['entities', 'relationships', 'audits'];
// Audits lines and areas can count the distinct values of an attribute instead of the events
const AUDITS_DISTINCT_COUNT_TYPES = ['line', 'area'];

// Relationships the relationships widgets display, as the front restricts them (RELATIONSHIP_WIDGETS_TYPES in
// opencti-front/src/utils/widget/widgetUtils.tsx): the knowledge relationships, the sightings, and the content and the
// labels of the containers. Not the other references of the elements (markings, authors, external references...).
const RELATIONSHIP_WIDGETS_TYPES = [ABSTRACT_STIX_CORE_RELATIONSHIP, STIX_SIGHTING_RELATIONSHIP, RELATION_OBJECT, RELATION_OBJECT_LABEL];

/**
 * Types every element of the dataset belongs to, read from a top level "entity type = ..." filter, or
 * "relationship type = ..." for relationships. Empty when the filters do not restrict the type for sure.
 * Same rule as the front (getBreakdownEntityTypes in widgetBreakdown.ts).
 */
export const getBreakdownEntityTypes = (filters?: FilterGroup | null, typeFilterKey = TYPE_FILTER): string[] => {
  if (!filters) return [];
  // Stored filters can miss a key
  const topFilters = filters.filters ?? [];
  const isRestrictingGroup = filters.mode === FilterMode.And || topFilters.length + (filters.filterGroups?.length ?? 0) === 1;
  // Manifest filters can hold the key as a string or as a list
  const typeFilter = topFilters.find((filter) => [filter.key].flat().includes(typeFilterKey));
  const typeValues = typeFilter?.values ?? [];
  // Several types in "and" only keep the elements of every type, while a single one restricts the type whatever the mode
  const isTypeIntersection = typeFilter?.mode === FilterMode.And && typeValues.length > 1;
  if (!isRestrictingGroup || !typeFilter || (typeFilter.operator && typeFilter.operator !== FilterOperator.Eq) || isTypeIntersection) {
    return [];
  }
  return typeValues.filter((value): value is string => typeof value === 'string');
};

// A dataset of draft workspaces only, as the front reads it (isDraftWorkspaceFilterGroup in filtersUtils.tsx)
const isDraftWorkspaceDataset = (filters?: FilterGroup | null) => {
  // Manifest filters can hold the key as a string or as a list
  const typeFilter = (filters?.filters ?? []).find((filter) => [filter.key].flat().includes(TYPE_FILTER));
  const types = typeFilter?.values ?? [];
  return types.length > 0 && types.every((type) => type === ENTITY_TYPE_DRAFT_WORKSPACE);
};

/**
 * Whether the stored widget can be broken down: a breakdown expands the single dataset of a time series widget, counting
 * its entities, relationships or events, outside the drafts. A relationships widget can also hold entities datasets: they
 * cannot be broken down as relationships. A widget edited without the breakdown feature, or imported, can keep a
 * breakdown it cannot have: the dashboards draw its regular chart.
 * Same rule as the front (canWidgetBreakDown in opencti-front/src/utils/widget/widgetBreakdown.ts), read on the widget of
 * the private manifest: its datasets keep their filters there, their saved filters and dashboard variables resolved.
 */
export const canWidgetBreakDown = (widget: Pick<PublicDashboardCachedWidget, 'type' | 'perspective' | 'dataSelection'>) => {
  const { type, perspective, dataSelection = [] } = widget;
  const [dataset] = dataSelection;
  return !!perspective && BREAKDOWN_PERSPECTIVES.includes(perspective)
    && TIME_SERIES_WIDGET_TYPES.includes(type)
    && dataSelection.length === 1
    && (dataset.perspective ?? perspective) === perspective
    && !isDraftWorkspaceDataset(dataset.filters)
    && !(perspective === 'audits' && AUDITS_DISTINCT_COUNT_TYPES.includes(type) && dataset.unique === true);
};

// Points a public breakdown counts at most, its series times its dates. Anyone with the link picks the period: the
// breakdown API would accept up to 50,000 of them (TIME_SERIES_BREAKDOWN_MAX_BUCKETS), while its charts never draw more
// than 5,000, the most points of a line (MAX_RENDERED_LINE_POINTS, the bars and the heatmaps draw fewer, in
// opencti-front/src/components/dashboard/timeSeriesBreakdownRendering.ts).
export const PUBLIC_BREAKDOWN_MAX_POINTS = 5000;
// Start of the bucket of a date, for each interval, as the date histogram aligns them (computeTimeSeriesRange in utils.ts)
const BUCKET_START_UNITS: Record<string, unitOfTime.StartOf> = { year: 'year', quarter: 'quarter', month: 'month', week: 'isoWeek', day: 'day', hour: 'hour' };

/**
 * Start date of a public breakdown: the requested one, moved forward when the period would count more points than
 * PUBLIC_BREAKDOWN_MAX_POINTS for this many series, so that the axis keeps the most recent dates that fit. The end date
 * is kept, now without one, as for the API.
 */
export const clampPublicBreakdownStartDate = (startDate: any, endDate: any, interval: string, seriesCount: number) => {
  // The API refuses the invalid limits itself
  if (!Number.isInteger(seriesCount) || seriesCount < 1) {
    return startDate;
  }
  const maxIntervals = Math.max(1, Math.floor(PUBLIC_BREAKDOWN_MAX_POINTS / seriesCount));
  const end = endDate ?? new Date();
  // Refuses an unsupported interval, as the API does
  if (countTimeSeriesIntervals(startDate, end, interval) <= maxIntervals) {
    return startDate;
  }
  // The bucket of the end date and the ones before it
  return moment.utc(end).startOf(BUCKET_START_UNITS[interval]).subtract(maxIntervals - 1, `${interval}s` as DurationInputArg2).toDate();
};

/**
 * Arguments of the breakdown API for a public widget. Every setting of a breakdown is read from the stored widget,
 * never from the request of the visitor, who only gives the period. The audits widgets can carry a breakdown too, but
 * the logs have no public API.
 */
export const buildPublicBreakdownArgs = (
  args: PublicBreakdownRequest,
  widget: PublicBreakdownWidget,
  breakdownPerspective: PublicBreakdownPerspective,
) => {
  const { type, perspective, dataSelection, parameters } = widget;
  if (!parameters?.breakdownBy) {
    throw UnsupportedError('This widget has no breakdown', { widgetId: args.widgetId });
  }
  // The public manifest serves it without its breakdown: the public dashboards draw its regular chart
  if (!canWidgetBreakDown(widget)) {
    throw FunctionalError('This widget cannot be broken down', { widgetId: args.widgetId, type, datasetsCount: dataSelection.length });
  }
  // Each perspective has its own query, the public dashboards asking the one of the widget
  if (perspective !== breakdownPerspective) {
    throw FunctionalError('This widget is broken down on another perspective', { widgetId: args.widgetId, perspective });
  }
  const [selection] = dataSelection;
  // The histogram is anchored on the start date: without it the series would silently collapse on today
  if (!args.startDate) {
    throw FunctionalError('A start date is required for a time series breakdown');
  }
  // The API has none: daily, as the other time series of the public widgets (publicStixCoreObjectsMultiTimeSeries)
  const interval = parameters.interval ?? 'day';
  // As many series as the API draws at most: its limit, and Other when it is requested
  const seriesCount = (parameters.breakdownLimit ?? TIME_SERIES_BREAKDOWN_DEFAULT_LIMIT) + (parameters.breakdownOther === true ? 1 : 0);
  // The settings the widget leaves out get the defaults of the breakdown API (timeSeriesBreakdown in middleware.ts):
  // 10 series, the highest values first, without Other
  const breakdownArgs = {
    field: parameters.breakdownBy,
    dateAttribute: selection.date_attribute,
    // The dates of the response tell the period the visitor gets
    startDate: clampPublicBreakdownStartDate(args.startDate, args.endDate, interval, seriesCount),
    endDate: args.endDate,
    interval,
    limit: parameters.breakdownLimit,
    orderMode: parameters.breakdownOrder,
    includeOther: parameters.breakdownOther,
  };
  if (breakdownPerspective === 'entities') {
    return {
      ...breakdownArgs,
      filters: selection.filters,
      // Without types, every entity (extractStixCoreObjectTypesFromArgs in stixCoreObject.js)
      types: getBreakdownEntityTypes(selection.filters),
    };
  }
  return {
    ...breakdownArgs,
    // Restricted to the relationships the widget displays, as the private breakdown: without a relationship type,
    // the references of the elements would be counted too, and could fill the top values
    filters: addFilter(selection.filters, TYPE_FILTER, RELATIONSHIP_WIDGETS_TYPES),
    // The same relationships as publicStixRelationshipsMultiTimeSeries
    dynamicFrom: selection.dynamicFrom,
    dynamicTo: selection.dynamicTo,
    // Without types, every type the filters above allow
    relationship_type: getBreakdownEntityTypes(selection.filters, RELATION_TYPE_FILTER),
  };
};

/**
 * Runs a public breakdown, its refusals only saying why: the same message, and in their data their reason alone
 * (BREAKDOWN_REFUSAL_REASONS in utils.ts), which the public dashboards tell their visitors. The breakdown API adds the
 * requested types to some of them, read from the stored filters the public manifest strips on purpose. Its other
 * errors are left as they are.
 */
export const withPublicBreakdownRefusals = async <T>(breakdown: () => Promise<T>): Promise<T> => {
  try {
    return await breakdown();
  } catch (error) {
    const { message, extensions } = error as GraphQLError;
    if (extensions?.code === FUNCTIONAL_ERROR) {
      const { reason } = (extensions.data ?? {}) as { reason?: string };
      throw FunctionalError(message, { reason });
    }
    throw error;
  }
};
