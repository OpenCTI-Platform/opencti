import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { getEntityTypeThreeFirstLevelsFilterValues } from 'src/utils/filters/filtersUtils';
import type { WidgetColumn, WidgetHost, WidgetPerspective } from 'src/utils/widget/widget';

export const getEntityTypeFromFilters = (filterGroup?: FilterGroup | null): string | undefined => {
  if (!filterGroup) return undefined;

  const entityTypeFilters = getEntityTypeThreeFirstLevelsFilterValues(filterGroup);
  const hasSingleEntityType = entityTypeFilters.length === 1;
  const otherFiltersLength = filterGroup.filters.filter((filter) => !['entity_type', 'relationship_type'].includes(filter.key)).length;

  if (hasSingleEntityType && filterGroup.mode === 'and') {
    return entityTypeFilters[0];
  }

  if (hasSingleEntityType && filterGroup.mode === 'or' && otherFiltersLength === 0) {
    return entityTypeFilters[0];
  }

  return undefined;
};

const hasEntityTypeFilter = (group: FilterGroup): boolean => {
  return group.filters.some(({ key }) => key === 'entity_type')
    || group.filterGroups.some(hasEntityTypeFilter);
};

export const getWidgetColumnsEntityType = (
  filterGroup: FilterGroup | null | undefined,
  perspective: WidgetPerspective | null | undefined,
  host: WidgetHost,
): string | undefined => {
  const entityTypeFromFilters = getEntityTypeFromFilters(filterGroup);
  if (entityTypeFromFilters) {
    return entityTypeFromFilters;
  }

  if (filterGroup && hasEntityTypeFilter(filterGroup)) {
    return undefined;
  }

  if (perspective !== 'entities') {
    return undefined;
  }

  if (host.kind === 'fintelTemplate') {
    return host.fintelEntityType;
  }

  if (host.kind === 'custom-view') {
    return host.customViewTargetEntityType;
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
