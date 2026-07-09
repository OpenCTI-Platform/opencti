import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from 'src/utils/widget/widget';
import { graphql } from 'react-relay';
import { buildFiltersForCustomView, removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes } from 'src/utils/filters/filtersUtils';
import { type FilterDefinition } from 'src/utils/hooks/useAuth';
import { computeRelativeDate, dayStartDate, formatDate } from 'src/utils/Time';
import { fetchQuery } from 'src/relay/environment';
import type { dashboardVizUtilsSavedFilterQuery$data } from './__generated__/dashboardVizUtilsSavedFilterQuery.graphql';
import { DashboardConfig } from './dashboard-types';

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
export const resolveDataSelection = ({
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
  const updatedDataSelection = dataSelection.map((data) => {
      let filters = [data.filters, data.dynamicFrom, data.dynamicTo];
      // Handle eventual saved filters
      if (data.filters_id) {
        fetchQuery(savedFilterQuery, { id: data.filters_id }).toPromise().then((data) => {
          const result = data as dashboardVizUtilsSavedFilterQuery$data;
          if (!result?.savedFilter) {
            isMissingSavedFilters = true;
          } else {
            filters[0] = JSON.parse(result.savedFilter.filters);
          }
        });
      }
      if (data.dynamicFrom_id) {
        fetchQuery(savedFilterQuery, { id: data.dynamicFrom_id }).toPromise().then((data) => {
          const result = data as dashboardVizUtilsSavedFilterQuery$data;
          if (!result?.savedFilter) {
            isMissingSavedFilters = true;
          } else {
            filters[1] = JSON.parse(result.savedFilter.filters);
          }
        });
      }
      if (data.dynamicTo_id) {
        fetchQuery(savedFilterQuery, { id: data.dynamicTo_id }).toPromise().then((data) => {
          const result = data as dashboardVizUtilsSavedFilterQuery$data;
          if (!result?.savedFilter) {
            isMissingSavedFilters = true;
          } else {
            filters[2] = JSON.parse(result.savedFilter.filters);
          }
        });
      }
      // For custom-view widgets, resolve SELF_ID placeholders with the actual host entity ID
      if (host?.kind === 'custom-view') {
        const resolvedFilters = filters.map((f) => buildFiltersForCustomView(f, host.customViewTargetEntityId));
        hostEntityNeeded = hostEntityNeeded || filters.some((f, i) => f !== resolvedFilters[i]);
        filters = resolvedFilters;
      }
      return {
        ...data,
        filters: removeIdAndIncorrectKeysFromFilterGroupObject(filters[0], availableFilterKeysMain),
        dynamicFrom: removeIdAndIncorrectKeysFromFilterGroupObject(filters[1], availableFilterKeysSecondary),
        dynamicTo: removeIdAndIncorrectKeysFromFilterGroupObject(filters[2], availableFilterKeysSecondary),
      };
    });
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
