import { FunctionalError, UnsupportedError } from '../../config/errors';
import { type FilterGroup, FilterMode, FilterOperator, type QueryPublicStixCoreObjectsTimeSeriesBreakdownArgs } from '../../generated/graphql';
import { ABSTRACT_STIX_CORE_RELATIONSHIP } from '../../schema/general';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { RELATION_OBJECT, RELATION_OBJECT_LABEL } from '../../schema/stixRefRelationship';
import { addFilter } from '../../utils/filtering/filtering-utils';
import { RELATION_TYPE_FILTER, TYPE_FILTER } from '../../utils/filtering/filtering-constants';
import type { PublicDashboardCachedWidget } from './publicDashboard-types';

// Perspectives with a public breakdown API: the logs of the audits widgets have none
type PublicBreakdownPerspective = 'entities' | 'relationships';
type PublicBreakdownRequest = Pick<QueryPublicStixCoreObjectsTimeSeriesBreakdownArgs, 'widgetId' | 'startDate' | 'endDate'>;
type PublicBreakdownWidget = Pick<PublicDashboardCachedWidget, 'type' | 'perspective' | 'dataSelection' | 'parameters'>;

// Widgets drawing a time series, the only ones a breakdown expands (the 'timeseries' category of the front widgets)
const TIME_SERIES_WIDGET_TYPES = ['vertical-bar', 'line', 'area', 'heatmap'];

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

/**
 * Arguments of the breakdown API for a public widget. Every setting of a breakdown is read from the stored widget,
 * never from the request of the visitor, who only gives the period. A widget of another perspective can carry a
 * breakdown too (an audits widget, whose logs have no public API).
 */
export const buildPublicBreakdownArgs = (
  args: PublicBreakdownRequest,
  widget: PublicBreakdownWidget,
  breakdownPerspective: PublicBreakdownPerspective,
) => {
  const { type, perspective, dataSelection, parameters } = widget;
  if (perspective !== breakdownPerspective || !parameters?.breakdownBy) {
    throw UnsupportedError('This widget has no breakdown', { widgetId: args.widgetId });
  }
  // A widget edited without the breakdown feature, or imported, can keep a breakdown it cannot have: the private
  // dashboards draw its regular chart. Same rule as the front (canWidgetBeBrokenDown in widgetBreakdown.ts): a time
  // series of a single dataset, of the elements of the widget (a relationships widget can also hold entities datasets).
  const [selection] = dataSelection;
  if (!TIME_SERIES_WIDGET_TYPES.includes(type) || dataSelection.length !== 1 || (selection.perspective ?? perspective) !== perspective) {
    throw FunctionalError('This widget cannot be broken down', { widgetId: args.widgetId, type, datasetsCount: dataSelection.length });
  }
  // The histogram is anchored on the start date: without it the series would silently collapse on today
  if (!args.startDate) {
    throw FunctionalError('A start date is required for a time series breakdown');
  }
  // The settings the widget leaves out get the defaults of the breakdown API (timeSeriesBreakdown in middleware.ts):
  // 10 series, the highest values first, without Other
  const breakdownArgs = {
    field: parameters.breakdownBy,
    dateAttribute: selection.date_attribute,
    startDate: args.startDate,
    endDate: args.endDate,
    // The API has none: daily, as the other time series of the public widgets (publicStixCoreObjectsMultiTimeSeries)
    interval: parameters.interval ?? 'day',
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
