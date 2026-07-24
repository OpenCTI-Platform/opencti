import type { WidgetHost, WidgetDataSelection, WidgetPerspective } from 'src/utils/widget/widget';
import { graphql } from 'react-relay';
import { buildFiltersForCustomView, removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes } from 'src/utils/filters/filtersUtils';
import { type FilterDefinition } from 'src/utils/hooks/useAuth';
import { computeRelativeDate, dayStartDate, formatDate } from 'src/utils/Time';
import { fetchQuery } from 'src/relay/environment';
import { DashboardConfig } from './dashboard-types';
import { dashboardVizUtilsSavedFilterQuery$data } from './__generated__/dashboardVizUtilsSavedFilterQuery.graphql';

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
 * Fetches a saved filter by ID and returns its parsed filters content.
 * Returns null if the filter could not be resolved.
 */
const fetchSavedFilterContent = async (filterId: string) => {
  try {
    const result = await fetchQuery(savedFilterQuery, { id: filterId }).toPromise() as dashboardVizUtilsSavedFilterQuery$data | undefined;
    if (!result?.savedFilter) return null;
    return JSON.parse(result.savedFilter.filters);
  } catch {
    return null;
  }
};

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
      const savedFilterIds = [data.filters_id, data.dynamicFrom_id, data.dynamicTo_id];
      for (let i = 0; i < savedFilterIds.length; i += 1) {
        const savedFilterId = savedFilterIds[i];
        if (savedFilterId) { // if a saved filter id is defined
          const resolved = await fetchSavedFilterContent(savedFilterId); // fetch the saved filter content
          if (!resolved) { // the saved filter is missing or not accessible
            isMissingSavedFilters = true;
          } else {
            filters[i] = resolved; // replace the associated filter by the saved filter content
          }
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
