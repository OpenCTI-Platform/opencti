import { Filter, FilterGroup } from './filtersUtils';

type FiltersLocalStorageUtilProps<U> = {
  filters: FilterGroup,
} & U;

const updateFilters = (filters: FilterGroup, updateFn: (filter: Filter) => Filter): FilterGroup => {
  return {
    ...filters,
    filters: filters.filters
      .map(updateFn),
  } as FilterGroup;
};

export const handleAddFilterWithEmptyValueUtil = ({ filters, filter }: FiltersLocalStorageUtilProps<{
  filter: Filter
}>) => {
  return {
    ...filters,
    filters: [
      ...filters.filters,
      filter,
    ],
  };
};

export const handleChangeOperatorFiltersUtil = ({ filters, id, operator }: FiltersLocalStorageUtilProps<{
  id: string,
  operator: string
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id
    ? {
      ...f,
      operator,
      values: ['nil', 'not_nil'].includes(operator) ? [] : f.values,
    }
    : f));
};

export const handleSwitchLocalModeUtil = ({ filters, filter }: FiltersLocalStorageUtilProps<{
  filter: Filter
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === filter.id
    ? { ...f, mode: filter.mode === 'and' ? 'or' : 'and' }
    : f));
};

export const handleAddRepresentationFilterUtil = ({ filters, id, valueId }: FiltersLocalStorageUtilProps<{
  id: string,
  valueId: string
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [...f.values, valueId] } : f));
};

export const handleAddSingleValueFilterUtil = ({ filters, id, valueId }: FiltersLocalStorageUtilProps<{
  id: string,
  valueId?: string
}>): FilterGroup => {
  if (valueId) {
    return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [valueId] } : f));
  }
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [] } : f));
};

export const handleRemoveRepresentationFilterUtil = ({ filters, id, valueId }: FiltersLocalStorageUtilProps<{
  id: string,
  valueId: string
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id
    ? {
      ...f,
      values: f.values.filter((value) => value !== valueId),
    }
    : f));
};

export const handleRemoveFilterUtil = ({ filters, id }: FiltersLocalStorageUtilProps<{ id: string }>): FilterGroup => {
  return {
    ...filters,
    filters: filters.filters.filter((f) => f.id !== id),
  };
};

export const handleClearAllFiltersUtil = (filters?: Filter[]): FilterGroup => {
  return {
    filterGroups: [],
    filters: filters ? [...filters] : [],
    mode: 'and',
  };
};
