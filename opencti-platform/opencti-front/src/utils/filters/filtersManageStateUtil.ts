import { Filter, FilterGroup, FilterValue } from './filtersHelpers-types';
import { DEFAULT_WITHIN_FILTER_VALUES } from './filtersUtils';

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
  return updateFilters(filters, (f) => {
    if (f.id === id) {
      let values = [...f.values];
      if (['nil', 'not_nil'].includes(operator)) {
        values = [];
      } else if (operator === 'within' && f.operator !== 'within') {
        values = DEFAULT_WITHIN_FILTER_VALUES;
      } else if (f.operator === 'within' && operator !== 'within') {
        values = [];
      }
      return {
        ...f,
        operator,
        values,
      };
    }
    return f;
  });
};

export const handleSwitchLocalModeUtil = ({ filters, filter }: FiltersLocalStorageUtilProps<{
  filter: Filter
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === filter.id
    ? { ...f, mode: filter.mode === 'and' ? 'or' : 'and' }
    : f));
};

export const handleAddRepresentationFilterUtil = ({ filters, id, value }: FiltersLocalStorageUtilProps<{
  id: string,
  value: string | FilterValue
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [...f.values, value] } : f));
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

export const handleReplaceFilterValuesUtil = ({ filters, id, values }: FiltersLocalStorageUtilProps<{
  id: string,
  values: string[],
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values } : f));
};

export const handleRemoveRepresentationFilterUtil = ({ filters, id, value }: FiltersLocalStorageUtilProps<{
  id: string,
  value: string | FilterValue
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id
    ? {
      ...f,
      values: f.values.filter((v) => v !== value),
    }
    : f));
};

export const handleRemoveFilterUtil = ({ filters, id }: FiltersLocalStorageUtilProps<{ id: string }>): FilterGroup => {
  return {
    ...filters,
    filters: filters.filters.filter((f) => f.id !== id),
  };
};

export const handleChangeRepresentationFilterUtil = ({ filters, id, oldValue, newValue }:FiltersLocalStorageUtilProps<{
  id: string,
  oldValue: FilterValue,
  newValue: FilterValue,
}>): FilterGroup => {
  return updateFilters(
    filters,
    (f) => (f.id === id
      ? { ...f, values: f.values.filter((val) => val !== oldValue).concat([newValue]) }
      : f),
  );
};
