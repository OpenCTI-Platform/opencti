import { Dispatch, SetStateAction } from 'react';
import { Filter, FilterGroup, filtersUsedAsApiParameters, FilterValue } from './filtersUtils';
import { LocalStorage } from '../hooks/useLocalStorageModel';

type FiltersLocalStorageUtilProps<U> = {
  viewStorage: LocalStorage,
  setValue: Dispatch<SetStateAction<LocalStorage>>
} & U;

const setFiltersValue = (setValue: Dispatch<SetStateAction<LocalStorage>>, filters: FilterGroup, latestAddFilterId?: string) => {
  setValue((c) => ({
    ...c,
    filters,
    latestAddFilterId,
  }));
};

const sortSpecificFilterAtFirst = (a: Filter, b: Filter) => {
  return filtersUsedAsApiParameters.indexOf(b.key) - filtersUsedAsApiParameters.indexOf(a.key);
};
const updateFilters = (viewStorage: LocalStorage, setValue: Dispatch<SetStateAction<LocalStorage>>, updateFn: (filter: Filter) => Filter) => {
  if (viewStorage.filters) {
    const newBaseFilters: FilterGroup = {
      ...viewStorage.filters,
      filters: viewStorage.filters.filters
        .map(updateFn)
        .sort(sortSpecificFilterAtFirst),
    };
    setFiltersValue(setValue, newBaseFilters);
  }
};

export const handleAddFilterWithEmptyValueUtil = ({ viewStorage, setValue, filter }: FiltersLocalStorageUtilProps<{
  filter: Filter
}>) => {
  if (viewStorage.filters) {
    const newBaseFilters = {
      ...viewStorage.filters,
      filters: [
        ...viewStorage.filters.filters,
        filter,
      ].sort(sortSpecificFilterAtFirst),
    };
    setFiltersValue(setValue, newBaseFilters, filter.id);
  }
};

export const handleChangeOperatorFiltersUtil = ({ viewStorage, setValue, id, operator }: FiltersLocalStorageUtilProps<{
  id: string,
  operator: string
}>) => {
  updateFilters(viewStorage, setValue, (f) => (f.id === id
    ? {
      ...f,
      operator,
      values: ['nil', 'not_nil'].includes(operator) ? [] : f.values,
    }
    : f));
};

export const handleSwitchLocalModeUtil = ({ viewStorage, setValue, filter }: FiltersLocalStorageUtilProps<{
  filter: Filter
}>) => {
  updateFilters(viewStorage, setValue, (f) => (f.id === filter.id
    ? { ...f, mode: filter.mode === 'and' ? 'or' : 'and' }
    : f));
};

export const handleAddRepresentationFilterUtil = ({ viewStorage, setValue, id, value }: FiltersLocalStorageUtilProps<{
  id: string,
  value: FilterValue,
}>) => {
  updateFilters(
    viewStorage,
    setValue,
    (f) => (f.id === id ? { ...f, values: [...f.values, value] } : f),
  );
};

export const handleChangeRepresentationFilterUtil = ({ viewStorage, setValue, id, oldValue, newValue }: FiltersLocalStorageUtilProps<{
  id: string,
  oldValue: any,
  newValue: any,
}>) => {
  updateFilters(
    viewStorage,
    setValue,
    (f) => (f.id === id
      ? { ...f, values: f.values.filter((val) => val !== oldValue).concat([newValue]) }
      : f),
  );
};

export const handleAddSingleValueFilterUtil = ({ viewStorage, setValue, id, value }: FiltersLocalStorageUtilProps<{
  id: string,
  value?: FilterValue
}>) => {
  if (value) {
    updateFilters(viewStorage, setValue, (f) => (f.id === id ? { ...f, values: [value] } : f));
  } else {
    updateFilters(viewStorage, setValue, (f) => (f.id === id ? { ...f, values: [] } : f));
  }
};

export const handleRemoveRepresentationFilterUtil = ({ viewStorage, setValue, id, value }: FiltersLocalStorageUtilProps<{
  id: string,
  value: FilterValue
}>) => {
  updateFilters(viewStorage, setValue, (f) => {
    console.log('result', {
      ...f,
      values: f.values.filter((value) => value !== valueId),
    });
    return (f.id === id
      ? {
        ...f,
        values: f.values.filter((v) => v !== value),
      }
      : f);
  });
};

export const handleRemoveFilterUtil = ({ viewStorage, setValue, id }: FiltersLocalStorageUtilProps<{ id?: string }>) => {
  if (viewStorage.filters) {
    const newBaseFilters: FilterGroup = {
      ...viewStorage.filters,
      filters: viewStorage.filters.filters.filter((f) => f.id !== id),
    };
    setFiltersValue(setValue, newBaseFilters);
  }
};
