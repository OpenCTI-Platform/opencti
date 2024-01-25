import { Dispatch, SetStateAction } from 'react';
import { Filter, FilterGroup, FilterValue } from './filtersUtils';
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

const updateFilters = (viewStorage: LocalStorage, setValue: Dispatch<SetStateAction<LocalStorage>>, updateFn: (filter: Filter) => Filter) => {
  if (viewStorage.filters) {
    const newBaseFilters: FilterGroup = {
      ...viewStorage.filters,
      filters: viewStorage.filters.filters
        .map(updateFn),
    };
    setFiltersValue(setValue, newBaseFilters);
  }
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
  oldValue: FilterValue,
  newValue: FilterValue,
}>) => {
  updateFilters(
    viewStorage,
    setValue,
    (f) => (f.id === id
      ? { ...f, values: f.values.filter((val) => val !== oldValue).concat([newValue]) }
      : f),
  );
};

export const handleRemoveRepresentationFilterUtil = ({ viewStorage, setValue, id, value }: FiltersLocalStorageUtilProps<{
  id: string,
  value: FilterValue
}>) => {
  updateFilters(viewStorage, setValue, (f) => (f.id === id
    ? {
      ...f,
      values: f.values.filter((v) => v !== value),
    }
    : f));
};
