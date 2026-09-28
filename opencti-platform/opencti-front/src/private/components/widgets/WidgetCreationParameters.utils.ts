import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { getEntityTypeThreeFirstLevelsFilterValues } from 'src/utils/filters/filtersUtils';
import type { WidgetColumn } from 'src/utils/widget/widget';

export const getEntityTypeFromFilters = (filterGroup?: FilterGroup | null): string | undefined => {
  if (!filterGroup) return undefined;

  const entityTypeFilters = getEntityTypeThreeFirstLevelsFilterValues(filterGroup);
  const hasSingleEntityType = entityTypeFilters.length === 1;
  const otherFiltersLength = filterGroup.filters.filter((filter) => filter.key !== 'entity_type').length;

  if (hasSingleEntityType && filterGroup.mode === 'and') {
    return entityTypeFilters[0];
  }

  if (hasSingleEntityType && filterGroup.mode === 'or' && otherFiltersLength === 0) {
    return entityTypeFilters[0];
  }

  return undefined;
};

export const mergeAvailableAndSelectedColumns = (
  availableColumns: WidgetColumn[],
  selectedColumns: WidgetColumn[],
) => {
  const availableAttributes = new Set(availableColumns.map((column) => column.attribute));
  const missingSelectedColumns = selectedColumns.filter(
    (column) => !availableAttributes.has(column.attribute),
  );
  return [...availableColumns, ...missingSelectedColumns];
};
