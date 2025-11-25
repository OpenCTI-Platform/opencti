import * as R from 'ramda';
import { Dispatch, SetStateAction, SyntheticEvent, useCallback, useState } from 'react';
import { v4 as uuid } from 'uuid';
import { type SavedFiltersSelectionData } from 'src/components/saved_filters/SavedFilterSelection';
import { OrderMode, PaginationOptions } from '../../components/list_lines';
import { emptyFilterGroup, findFilterFromKey, isFilterGroupNotEmpty, isUniqFilter, useFetchFilterKeysSchema } from '../filters/filtersUtils';
import { isEmptyField, isNotEmptyField, removeEmptyFields } from '../utils';
import { MESSAGING$ } from '../../relay/environment';
import {
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeOperatorFiltersUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleSwitchLocalModeUtil,
  handleChangeRepresentationFilterUtil,
  handleReplaceFilterValuesUtil,
} from '../filters/filtersManageStateUtil';
import { LocalStorage } from './useLocalStorageModel';
import useBus from './useBus';
import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from '../filters/filtersHelpers-types';

export interface NumberOfElements {
  number?: number;
  symbol?: string;
  original?: number;
}

export interface UseLocalStorageHelpers extends handleFilterHelpers {
  handleSearch: (value: string) => void;
  handleRemoveFilter: (key: string, op?: string, id?: string) => void;
  handleSort: (field: string, order: boolean) => void;
  handleAddFilter: HandleAddFilter;
  handleRemoveRepresentationFilter: (id: string, value: FilterValue) => void;
  handleAddRepresentationFilter: (id: string, value: FilterValue) => void;
  handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => void;
  handleAddSingleValueFilter: (id: string, value?: FilterValue) => void;
  handleReplaceFilterValues: (id: string, values: FilterValue[]) => void;
  handleSwitchFilter: HandleAddFilter;
  handleToggleExports: () => void;
  handleSetNumberOfElements: (value: NumberOfElements) => void;
  handleToggleTypes: (type: string) => void;
  handleClearTypes: () => void;
  handleAddProperty: (field: string, value: unknown) => void;
  handleChangeView: (value: string) => void;
  handleClearAllFilters: () => void;
  handleSetFilters: (filters: FilterGroup) => void;
  handleChangeSavedFilters: (savedFilters: SavedFiltersSelectionData) => void;
  handleRemoveSavedFilters: () => void;
}

const localStorageToPaginationOptions = (
  { searchTerm, filters, sortBy, orderAsc, ...props }: LocalStorage,
): PaginationOptions => {
  // Remove only display options, not query linked
  const localOptions = { ...props };
  delete localOptions.openExports;
  delete localOptions.selectAll;
  delete localOptions.redirectionMode;
  delete localOptions.selectedElements;
  delete localOptions.deSelectedElements;
  delete localOptions.numberOfElements;
  delete localOptions.view;
  delete localOptions.zoom;
  delete localOptions.latestAddFilterId;
  delete localOptions.latestAddFilterKey;
  delete localOptions.pageSize;
  delete localOptions.savedFilters;
  // Rebuild some pagination options
  const basePagination: PaginationOptions = { ...localOptions };
  if (searchTerm) {
    basePagination.search = searchTerm;
  }
  if (orderAsc || sortBy) {
    basePagination.orderMode = orderAsc ? OrderMode.asc : OrderMode.desc;
    basePagination.orderBy = sortBy;
  }
  basePagination.filters = isFilterGroupNotEmpty(filters) ? filters : undefined;
  return basePagination;
};

export type HandleAddFilter = (
  k: string,
  id: string | null,
  op?: string,
  event?: SyntheticEvent
) => void;

const buildParamsFromHistory = (params: LocalStorage) => {
  return removeEmptyFields({
    filters:
      params.filters && isFilterGroupNotEmpty(params.filters)
        ? JSON.stringify(params.filters)
        : undefined,
    zoom: JSON.stringify(params.zoom),
    searchTerm: params.searchTerm,
    sortBy: params.sortBy,
    orderAsc: params.orderAsc,
    timeField: params.timeField,
    dashboard: params.dashboard,
    redirectionMode: params.redirectionMode,
    pageSize: params.pageSize,
    view: params.view,
    types:
      params.types && params.types.length > 0
        ? params.types.join(',')
        : undefined,
  });
};

const searchParamsToStorage = (searchObject: URLSearchParams) => {
  const zoom = searchObject.get('zoom');
  const stringFilters = searchObject.get('filters');
  let filters = stringFilters ? JSON.parse(stringFilters) : undefined;
  if (filters && !filters.mode) { // if filters are in the old format
    // Remove the filters from local storage
    filters = undefined;
    // Remove the filters from the URL
    const currentUrl = window.location.href;
    const newUrl = currentUrl.split('?')[0];
    window.history.replaceState(null, '', newUrl);
    // Display a warning message
    setTimeout(() => { // delay the message to be sure the page is loaded
      MESSAGING$.notifyError('Your url contains filters in a deprecated format, parameters stored in the url have been removed.');
    }, 1000);
  }
  return removeEmptyFields({
    filters,
    zoom: zoom ? JSON.parse(zoom) : undefined,
    searchTerm: searchObject.get('searchTerm')
      ? searchObject.get('searchTerm')
      : undefined,
    sortBy: searchObject.get('sortBy'),
    types: searchObject.get('types')
      ? searchObject.get('types')?.split(',')
      : undefined,
    orderAsc: searchObject.get('orderAsc')
      ? searchObject.get('orderAsc') === 'true'
      : undefined,
    timeField: searchObject.get('timeField'),
    dashboard: searchObject.get('dashboard'),
    pageSize: searchObject.get('pageSize'),
    view: searchObject.get('view'),
  });
};

const setStoredValueToHistory = (
  initialValue: LocalStorage | undefined,
  valueToStore: LocalStorage,
) => {
  const searchParams = new URLSearchParams(window.location.search);
  const finalParams = searchParamsToStorage(searchParams);
  const urlParams = buildParamsFromHistory(valueToStore);
  if (!R.equals(urlParams, buildParamsFromHistory(finalParams))) {
    const effectiveParams = new URLSearchParams(urlParams);
    let newUrl = window.location.pathname;
    if (
      Object.entries(urlParams).some(
        ([k, v]) => initialValue?.[k as keyof LocalStorage] !== v,
      )
    ) {
      newUrl += `?${effectiveParams.toString()}`;
    }
    window.history.replaceState(null, '', newUrl);
  }
};

const useLocalStorage = <T extends LocalStorage = LocalStorage>(
  key: string,
  initialValue?: T,
  ignoreUri?: boolean,
  ignoreDispatch = false,
): [T, Dispatch<SetStateAction<T>>] => {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const finalParams = !ignoreUri
        ? searchParamsToStorage(searchParams)
        : null;
      // Get from local storage by key
      const item = window.localStorage.getItem(key);
      // Parse stored json or if none return initialValue
      let value = item ? JSON.parse(item) : null;
      if (isEmptyField(value)) {
        value = initialValue;
      }
      // Values from uri must be prioritized on initial loading
      // Localstorage must be rewritten to ensure consistency
      if (isNotEmptyField(finalParams)) {
        const initialState = { ...value, ...finalParams };
        window.localStorage.setItem(key, JSON.stringify(initialState));
        return initialState;
      }
      // Need to clear the local storage ?
      if (!R.equals(removeEmptyFields(value), value) || isEmptyField(item)) {
        const initialState = removeEmptyFields(value);
        window.localStorage.setItem(key, JSON.stringify(initialState));
        return initialState;
      }
      return value;
    } catch (_error) {
      // If error also return initialValue
      throw Error('Error while initializing values in local storage');
    }
  });

  const dispatch = useBus(key, (v) => {
    if (!R.equals(v, storedValue) && !ignoreDispatch) {
      setStoredValue(v);
    }
  });
  // Return a wrapped version of useState's setter function that ...
  // ... persists the new value to localStorage.
  const setValue = (
    value: T | ((val: T) => T),
  ) => {
    try {
      // Allow value to be a function so we have same API as useState
      let valueToStore = value instanceof Function ? value(storedValue) : value;
      valueToStore = removeEmptyFields(valueToStore) as T;
      // Save state
      setStoredValue(valueToStore);
      dispatch(key, valueToStore);
      // Save to local storage + re-align uri if needed
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
        if (!ignoreUri) {
          setStoredValueToHistory(initialValue, valueToStore);
        }
      }
    } catch (_error) {
      // A more advanced implementation would handle the error case
      throw Error('Error while setting values in local storage');
    }
  };
  // re-align uri if needed
  if (!ignoreUri) {
    setStoredValueToHistory(initialValue, storedValue);
  }
  return [storedValue, setValue];
};

export type PaginationLocalStorage<U = Record<string, unknown>> = {
  viewStorage: LocalStorage;
  helpers: UseLocalStorageHelpers;
  paginationOptions: U;
  localStorageKey: string;
};

export const usePaginationLocalStorage = <U>(
  key: string,
  initialValue: LocalStorage,
  ignoreUri?: boolean,
): PaginationLocalStorage<U> => {
  const [viewStorage, setValue] = useLocalStorage(key, initialValue, ignoreUri);

  const callback = useCallback((v: LocalStorage) => {
    setValue(v);
  }, [viewStorage]);

  const dispatch = useBus(`${key}_paginationStorage`, callback);

  const paginationOptions = localStorageToPaginationOptions({
    count: viewStorage.pageSize ? Number.parseInt(viewStorage.pageSize, 10) : 25,
    ...viewStorage,
  });

  const filterKeysSchema = useFetchFilterKeysSchema();

  const [storedSortBy, setStoredSortBy] = useState(viewStorage.sortBy);
  const [storedOrderAsc, setStoredOrderAsc] = useState(viewStorage.orderAsc);

  const helpers: UseLocalStorageHelpers = {
    handleChangeSavedFilters: (savedFilters: SavedFiltersSelectionData) => {
      const newValue = {
        ...viewStorage,
        filters: JSON.parse(savedFilters.filters),
        latestAddFilterId: undefined,
        latestAddFilterKey: undefined,
        savedFilters,
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleRemoveSavedFilters: () => {
      const newValue = {
        ...viewStorage,
        savedFilters: undefined,
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleSearch: (value: string) => {
      const newValue = (value === '') ? {
        ...viewStorage,
        searchTerm: value,
        sortBy: storedSortBy === '_score' ? undefined : storedSortBy,
        orderAsc: storedOrderAsc,
      } : {
        ...viewStorage,
        searchTerm: value,
        sortBy: '_score',
        orderAsc: false,
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleRemoveFilterById: (id: string) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        const newValue = {
          ...viewStorage,
          filters: handleRemoveFilterUtil({ filters, id }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleRemoveFilter: (k: string, op = 'eq', id?: string) => {
      if (viewStorage.filters) {
        if (id) {
          const filter = findFilterFromKey(viewStorage.filters.filters, k, op);
          if (filter) {
            const values = filter.values.filter((val) => val !== id);
            if (values && values.length > 0) { // values is not empty: only remove 'id' from 'values'
              const newFilterElement = {
                id: uuid(),
                key: k,
                values,
                operator: filter.operator ?? 'eq',
                mode: filter.mode ?? 'or',
              };
              const newBaseFilters = {
                ...viewStorage.filters,
                filters: [
                  ...viewStorage.filters.filters
                    .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
                  newFilterElement, // remove value=id
                ],
              };
              const newValue = {
                ...viewStorage,
                filters: newBaseFilters,
              };
              setValue(newValue);
              dispatch(`${key}_paginationStorage`, newValue);
            } else { // values is empty: remove the filter with key=k and operator=op
              const newBaseFilters = {
                ...viewStorage.filters,
                filters: [
                  ...viewStorage.filters.filters
                    .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
                ],
              };
              const newValue = {
                ...viewStorage,
                filters: newBaseFilters,
              };
              setValue(newValue);
              dispatch(`${key}_paginationStorage`, newValue);
            }
          }
        } else {
          const newBaseFilters = {
            ...viewStorage.filters,
            filters: viewStorage.filters.filters
              .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
          };
          const newValue = {
            ...viewStorage,
            filters: newBaseFilters,
          };
          setValue(newValue);
          dispatch(`${key}_paginationStorage`, newValue);
        }
      }
    },
    handleSort: (field: string, order: boolean) => {
      const newValue = {
        ...viewStorage,
        sortBy: field,
        orderAsc: order,
      };
      setStoredSortBy(field);
      setStoredOrderAsc(order);
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleAddProperty: (field: string, value: unknown) => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      if (!R.equals(viewStorage[field], value)) {
        const newValue = {
          ...viewStorage,
          [field]: value,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleAddFilter: (
      k: string,
      id: string | null,
      defaultOp = 'eq',
      event?: SyntheticEvent,
    ) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      let op = defaultOp;
      if (id === null && op === 'eq') { // handle clicking on 'no label' in entities list
        op = 'nil';
      }
      const filter = viewStorage.filters
        ? findFilterFromKey(viewStorage.filters.filters, k, op)
        : undefined;
      if (viewStorage.filters && filter) {
        let newValues: string[] = [];
        if (id !== null) {
          newValues = isUniqFilter(k, filterKeysSchema)
            ? [id]
            : R.uniq([...filter.values, id]);
        }
        const newFilterElement = {
          id: uuid(),
          key: k,
          values: newValues,
          operator: op,
          mode: 'or',
        };
        const newBaseFilters = {
          ...viewStorage.filters,
          filters: [
            ...viewStorage.filters.filters.map((f) => (f.key === k && f.operator === op ? newFilterElement : f)),
          ],
        };
        const newValue = {
          ...viewStorage,
          filters: newBaseFilters,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      } else {
        const newFilterElement = {
          id: uuid(),
          key: k,
          values: id !== null ? [id] : [],
          operator: op,
          mode: 'or',
        };
        const newBaseFilters = viewStorage.filters ? {
          ...viewStorage.filters,
          filters: [...viewStorage.filters.filters, newFilterElement], // add new filter
        } : {
          mode: 'and',
          filterGroups: [],
          filters: [newFilterElement],
        };
        const newValue = {
          ...viewStorage,
          filters: newBaseFilters,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleRemoveRepresentationFilter: (
      id: string,
      value: string,
    ) => {
      if (viewStorage?.filters) {
        const filters = viewStorage?.filters;
        const newValue = {
          ...viewStorage,
          filters: handleRemoveRepresentationFilterUtil({ filters, id, value }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleAddRepresentationFilter: (id: string, value: string) => {
      if (value === null) { // handle clicking on 'no label' in entities list
        const findCorrespondingFilter = viewStorage.filters?.filters.find((f) => id === f.id);
        if (findCorrespondingFilter && ['objectLabel'].includes(findCorrespondingFilter.key)) {
          if (viewStorage.filters) {
            const newValue = {
              ...viewStorage,
              filters: handleChangeOperatorFiltersUtil({
                filters: viewStorage.filters,
                id,
                operator: findCorrespondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
              }),
              latestAddFilterId: id,
              latestAddFilterKey: findCorrespondingFilter.key,
            };
            setValue(newValue);
            dispatch(`${key}_paginationStorage`, newValue);
          }
        }
      } else if (viewStorage?.filters) {
        const { filters } = viewStorage;
        const newValue = {
          ...viewStorage,
          filters: handleAddRepresentationFilterUtil({ filters, id, value }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => {
      const filters = viewStorage?.filters;
      if (!filters) {
        return;
      }
      if (oldValue && newValue) {
        const newStorageValue = {
          ...viewStorage,
          filters: handleChangeRepresentationFilterUtil({ filters, id, oldValue, newValue }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newStorageValue);
        dispatch(`${key}_paginationStorage`, newStorageValue);
      } else if (oldValue) {
        const newStorageValue = {
          ...viewStorage,
          filters: handleRemoveRepresentationFilterUtil({ filters, id, value: oldValue }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newStorageValue);
        dispatch(`${key}_paginationStorage`, newStorageValue);
      } else if (newValue) {
        const newStorageValue = {
          ...viewStorage,
          filters: handleAddRepresentationFilterUtil({ filters, id, value: newValue }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newStorageValue);
        dispatch(`${key}_paginationStorage`, newStorageValue);
      }
    },
    handleReplaceFilterValues: (id: string, values: FilterValue[]) => {
      const filters = viewStorage?.filters;
      if (!filters) {
        return;
      }
      const newStorageValue = {
        ...viewStorage,
        filters: handleReplaceFilterValuesUtil({ filters, id, values }),
        latestAddFilterId: undefined,
        latestAddFilterKey: undefined,
      };
      setValue(newStorageValue);
      dispatch(`${key}_paginationStorage`, newStorageValue);
    },
    handleAddSingleValueFilter: (id: string, valueId?: string) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        const newValue = {
          ...viewStorage,
          filters: handleAddSingleValueFilterUtil({ filters, id, valueId }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleSwitchFilter: (
      k: string,
      id: string | null,
      op = 'eq',
      event?: SyntheticEvent,
    ) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      const newFilterElement = {
        id: uuid(),
        key: k,
        values: [id],
        operator: op,
        mode: 'or',
      };
      if (viewStorage.filters && findFilterFromKey(viewStorage.filters.filters, k, op)) {
        const newBaseFilters = {
          ...viewStorage.filters,
          filters: [
            ...viewStorage.filters.filters
              .filter((f) => f.key !== k || f.operator !== op), // remove filter with k as key and op as operator
            newFilterElement, // add new filter
          ],
        };
        const newValue = {
          ...viewStorage,
          filters: newBaseFilters,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      } else {
        const newBaseFilters = viewStorage.filters ? {
          ...viewStorage.filters,
          filters: [...viewStorage.filters.filters, newFilterElement], // set new filter
        } : {
          mode: 'and',
          filterGroups: [],
          filters: [newFilterElement],
        };
        const newValue = {
          ...viewStorage,
          filters: newBaseFilters,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleSwitchGlobalMode: () => {
      if (viewStorage.filters) {
        const newBaseFilters = {
          ...viewStorage.filters,
          mode: viewStorage.filters.mode === 'and' ? 'or' : 'and',
        };
        const newValue = {
          ...viewStorage,
          filters: newBaseFilters,
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleSwitchLocalMode: (filter: Filter) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        const newValue = {
          ...viewStorage,
          filters: handleSwitchLocalModeUtil({ filters, filter }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleChangeView: (value: string) => {
      const oldValue = viewStorage.view;
      const noReset = (oldValue === 'lines' && value === 'cards') || (oldValue === 'cards' && value === 'lines');
      const newValue = noReset
        ? {
          ...viewStorage,
          view: value,
        }
        : {
          ...viewStorage,
          filters: initialValue.filters ?? emptyFilterGroup,
          searchTerm: initialValue.searchTerm ?? '',
          savedFilters: undefined,
          view: value,
        };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleToggleExports: () => {
      const newValue = { ...viewStorage, openExports: !viewStorage.openExports };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleSetNumberOfElements: (nbElements: { number?: number; symbol?: string; original?: number; }) => {
      if (!R.equals(nbElements, viewStorage.numberOfElements)) {
        const { number, symbol, original } = nbElements;
        const newValue = {
          ...viewStorage,
          numberOfElements: {
            ...viewStorage.numberOfElements,
            ...(number ? { number } : { number: 0 }),
            ...(symbol ? { symbol } : { symbol: '' }),
            ...(original ? { original } : { original: 0 }),
          },
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleToggleTypes: (type: string) => {
      if (viewStorage.types?.includes(type)) {
        const newTypes = viewStorage.types.filter((t) => t !== type);
        const newValue = {
          ...viewStorage,
          types: newTypes,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      } else {
        const newTypes = viewStorage.types ? [...viewStorage.types, type] : [type];
        const newValue = {
          ...viewStorage,
          types: newTypes,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    handleClearTypes: () => {
      const newValue = {
        ...viewStorage,
        types: [],
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleClearAllFilters: () => {
      const newValue = {
        ...viewStorage,
        filters: initialValue.filters ?? emptyFilterGroup,
        searchTerm: initialValue.searchTerm ?? '',
        numberOfElements: viewStorage.numberOfElements,
        savedFilters: undefined,
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleSetFilters: (filters: FilterGroup) => {
      const newValue = {
        ...viewStorage,
        filters,
        latestAddFilterId: undefined,
        latestAddFilterKey: undefined,
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleAddFilterWithEmptyValue: (filter: Filter) => {
      const { filters } = viewStorage;
      const newValue = {
        ...viewStorage,
        filters: handleAddFilterWithEmptyValueUtil({ filters: filters ?? emptyFilterGroup, filter }),
        latestAddFilterId: filter.id,
        latestAddFilterKey: filter.key,
      };
      setValue(newValue);
      dispatch(`${key}_paginationStorage`, newValue);
    },
    handleChangeOperatorFilters: (id: string, operator: string) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        const newValue = {
          ...viewStorage,
          filters: handleChangeOperatorFiltersUtil({ filters, id, operator }),
          latestAddFilterId: undefined,
          latestAddFilterKey: undefined,
        };
        setValue(newValue);
        dispatch(`${key}_paginationStorage`, newValue);
      }
    },
    getLatestAddFilterId: () => {
      return viewStorage.latestAddFilterId;
    },
  };

  const removeEmptyFilter = paginationOptions.filters?.filters
    ?.filter((f) => ['nil', 'not_nil'].includes(f.operator ?? 'eq') || f.values.length > 0) ?? [];
  let filters;
  if (removeEmptyFilter.length > 0) {
    filters = {
      ...paginationOptions.filters,
      filters: removeEmptyFilter.map((filter: Filter) => {
        const removeIdFromFilter = { ...filter };
        delete removeIdFromFilter.id;
        return removeIdFromFilter;
      }),
    };
  } else {
    // In case where filter is empty but filterGroup exist
    const newFilters = {
      ...paginationOptions.filters,
      filters: removeEmptyFilter,
    } as FilterGroup;
    filters = isFilterGroupNotEmpty(newFilters) ? newFilters : undefined;
  }
  const cleanPaginationOptions = {
    ...paginationOptions,
    filters,
  };
  return {
    viewStorage,
    helpers,
    paginationOptions: cleanPaginationOptions as U,
    localStorageKey: key,
  };
};

export default useLocalStorage;
