import { WidgetDataSelection, WidgetHost, WidgetParameters, WidgetPerspective } from 'src/utils/widget/widget';
import { graphql } from 'react-relay';
import {
  buildFiltersAndOptionsForWidgets,
  buildFiltersForCustomView,
  getAvailableFilterKeysForEntityTypes,
  normalizeFilterGroupForBackend,
  removeIdAndIncorrectKeysFromFilterGroupObject,
} from 'src/utils/filters/filtersUtils';
import { type FilterDefinition } from 'src/utils/hooks/useAuth';
import { computeRelativeDate, dayStartDate, formatDate, monthsAgo, now } from 'src/utils/Time';
import { fetchQuery } from 'src/relay/environment';
import { DashboardConfig } from './dashboard-types';
import { dashboardVizUtilsSavedFilterQuery$data } from './__generated__/dashboardVizUtilsSavedFilterQuery.graphql';
import { getWidgetInterval } from 'src/utils/widget/widgetUtils';

export const savedFilterQuery = graphql`
  query dashboardVizUtilsSavedFilterQuery($id: ID!) {
    savedFilter(id: $id) {
      id
      name
      filters
      scope
    }
  }
`;

/**
 * Resolves widget data selections by cleaning filters based on the widget perspective,
 * substituting host entity IDs for custom views, and removing unavailable filter keys.
 * Returns the resolved selections along with flags indicating missing host entity or preview mode.
 */
export const resolveDataSelection = async ({
  filterKeysSchema,
  dataSelection,
  perspective,
  host,
}: {
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>;
  dataSelection: WidgetDataSelection[];
  perspective: WidgetPerspective;
  host?: WidgetHost;
}) => {
  let isMissingSavedFilters = false;
  let mainEntityTypes = ['Stix-Core-Object', 'DraftWorkspace'];
  if (perspective === 'relationships') {
    mainEntityTypes = ['stix-core-relationship', 'stix-sighting-relationship'];
  } else if (perspective === 'audits') {
    mainEntityTypes = ['History'];
  }
  const availableFilterKeysMain = getAvailableFilterKeysForEntityTypes(filterKeysSchema, mainEntityTypes, true);
  const availableFilterKeysSecondary = getAvailableFilterKeysForEntityTypes(filterKeysSchema, ['Stix-Core-Object'], true);
  let hostEntityNeeded = false;
  const updatedDataSelection = await Promise.all(
    dataSelection.map(async (data) => {
      const filters = [data.filters, data.dynamicFrom, data.dynamicTo];
      // Handle eventual saved filters
      if (data.filters_id) {
        try {
          const result = await fetchQuery(savedFilterQuery, { id: data.filters_id }).toPromise() as dashboardVizUtilsSavedFilterQuery$data | undefined;
          if (!result?.savedFilter) {
            isMissingSavedFilters = true;
          } else {
            filters[0] = JSON.parse(result.savedFilter.filters);
          }
        } catch {
          isMissingSavedFilters = true;
        }
      }
      if (data.dynamicFrom_id) {
        try {
          const result = await fetchQuery(savedFilterQuery, { id: data.dynamicFrom_id }).toPromise() as dashboardVizUtilsSavedFilterQuery$data | undefined;
          if (!result?.savedFilter) {
            isMissingSavedFilters = true;
          } else {
            filters[1] = JSON.parse(result.savedFilter.filters);
          }
        } catch {
          isMissingSavedFilters = true;
        }
      }
      if (data.dynamicTo_id) {
        try {
          const result = await fetchQuery(savedFilterQuery, { id: data.dynamicTo_id }).toPromise() as dashboardVizUtilsSavedFilterQuery$data | undefined;
          if (!result?.savedFilter) {
            isMissingSavedFilters = true;
          } else {
            filters[2] = JSON.parse(result.savedFilter.filters);
          }
        } catch {
          isMissingSavedFilters = true;
        }
      }
      // For custom-view widgets, resolve SELF_ID placeholders with the actual host entity ID
      let resolvedFilters = filters;
      if (host?.kind === 'custom-view') {
        resolvedFilters = filters.map((f) => buildFiltersForCustomView(f, host.customViewTargetEntityId));
        hostEntityNeeded = hostEntityNeeded || filters.some((f, i) => f !== resolvedFilters[i]);
      }
      return {
        ...data,
        filters: removeIdAndIncorrectKeysFromFilterGroupObject(resolvedFilters[0], availableFilterKeysMain),
        dynamicFrom: removeIdAndIncorrectKeysFromFilterGroupObject(resolvedFilters[1], availableFilterKeysSecondary),
        dynamicTo: removeIdAndIncorrectKeysFromFilterGroupObject(resolvedFilters[2], availableFilterKeysSecondary),
      };
    }));
  const isMissingHostEntity = host?.kind === 'custom-view'
    && hostEntityNeeded
    && !host.customViewTargetEntityId;
  const isPreviewMode = host?.kind === 'custom-view' && hostEntityNeeded && Boolean(host.customViewTargetEntityId) && host.previewMode;
  return {
    resolvedDataSelection: updatedDataSelection,
    isMissingHostEntity,
    isPreviewMode,
    isMissingSavedFilters,
  };
};

export const computeStartEndDates = (config?: DashboardConfig) => {
  const startDate = config?.relativeDate
    ? computeRelativeDate(config.relativeDate)
    : config?.startDate;

  const endDate = config?.relativeDate
    ? formatDate(dayStartDate(null, false))
    : config?.endDate;

  return { startDate, endDate };
};

/**
 * Builds the common base query variables for relationship widgets supporting multiple data selection.
 * Computes start/end dates from config, resolves dateAttribute,
 * builds and normalizes filters (including dynamicFrom/dynamicTo).
 *
 * Each widget can destructure the result and add its own specific fields.
 */
export const buildRelationshipMultiWidgetBaseQueryVariables = (
  dataSelection: WidgetDataSelection[],
  config: DashboardConfig,
  parameters?: WidgetParameters,
) => {
  const fallbackStart = monthsAgo(12);
  const fallbackEnd = now();
  const computed = computeStartEndDates(config);
  const startDate = computed.startDate ?? fallbackStart;
  const endDate = computed.endDate ?? fallbackEnd;

  const timeSeriesParameters = dataSelection.map((selection) => {
    const dateAttribute = selection.date_attribute?.length
      ? selection.date_attribute
      : 'created_at';
    const { filters } = buildFiltersAndOptionsForWidgets(selection.filters,
      {
        startDate,
        endDate,
        dateAttribute,
        isKnowledgeRelationshipWidget: true,
      });

    return {
      field: dateAttribute,
      filters: normalizeFilterGroupForBackend(filters),
      dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
      dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
    };
  });

  return {
    operation: 'count',
    startDate,
    endDate,
    interval: getWidgetInterval(parameters),
    timeSeriesParameters,
  };
};

/**
 * Builds the common base query variables for relationship widgets using a single data selection.
 * Computes start/end dates from config, resolves dateAttribute,
 * builds and normalizes filters (including dynamicFrom/dynamicTo),
 * and provides default ordering and pagination.
 *
 * Used by widgets like Timeline, Number, etc. that operate on a single selection.
 */
export const buildRelationshipSingleWidgetBaseQueryVariables = (
  selection: WidgetDataSelection,
  config: DashboardConfig,
) => {
  const dateAttribute = selection.date_attribute?.length
    ? selection.date_attribute
    : 'created_at';
  const { startDate, endDate } = computeStartEndDates(config);
  const { filters } = buildFiltersAndOptionsForWidgets(
    selection.filters,
    {
      startDate,
      endDate,
      dateAttribute,
      isKnowledgeRelationshipWidget: true,
    },
  );

  return {
    startDate,
    endDate,
    dateAttribute,
    filters: normalizeFilterGroupForBackend(filters),
    dynamicFrom: normalizeFilterGroupForBackend(selection.dynamicFrom),
    dynamicTo: normalizeFilterGroupForBackend(selection.dynamicTo),
  };
};
