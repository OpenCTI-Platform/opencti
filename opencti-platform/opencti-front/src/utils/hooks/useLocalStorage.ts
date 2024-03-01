import * as R from 'ramda';
import { Dispatch, SetStateAction, SyntheticEvent, useState } from 'react';
import { v4 as uuid } from 'uuid';
import { OrderMode, PaginationOptions } from '../../components/list_lines';
import { emptyFilterGroup, Filter, FilterGroup, FilterValue, findFilterFromKey, isFilterGroupNotEmpty, isUniqFilter } from '../filters/filtersUtils';
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
} from '../filters/filtersManageStateUtil';
import { LocalStorage } from './useLocalStorageModel';
import useAuth from './useAuth';

export interface handleFilterHelpers {
  handleSwitchGlobalMode: () => void;
  handleSwitchLocalMode: (filter: Filter) => void;
  handleRemoveRepresentationFilter: (id: string, valueId: string) => void;
  handleRemoveFilterById: (id: string) => void;
  handleChangeOperatorFilters: HandleOperatorFilter;
  handleAddSingleValueFilter: (id: string, valueId?: string) => void;
  handleAddRepresentationFilter: (id: string, valueId: string) => void;
  handleAddFilterWithEmptyValue: (filter: Filter) => void;
  handleClearAllFilters: (filters?: Filter[]) => void;
  getLatestAddFilterId: () => string | undefined;
  handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => void;
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
  handleSwitchFilter: HandleAddFilter;
  handleToggleExports: () => void;
  handleSetNumberOfElements: (value: {
    number?: number | string;
    symbol?: string;
    original?: number;
  }) => void;
  handleToggleTypes: (type: string) => void;
  handleClearTypes: () => void;
  handleAddProperty: (field: string, value: unknown) => void;
  handleChangeView: (value: string) => void;
  handleClearAllFilters: () => void;
}

const localStorageToPaginationOptions = (
  { searchTerm, filters, sortBy, orderAsc, ...props }: LocalStorage,
): PaginationOptions => {
  // Remove only display options, not query linked
  const localOptions = { ...props };
  delete localOptions.redirectionMode;
  delete localOptions.openExports;
  delete localOptions.selectAll;
  delete localOptions.redirectionMode;
  delete localOptions.selectedElements;
  delete localOptions.deSelectedElements;
  delete localOptions.numberOfElements;
  delete localOptions.view;
  delete localOptions.zoom;
  delete localOptions.latestAddFilterId;
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
  id: string,
  op?: string,
  event?: SyntheticEvent
) => void;

export type HandleOperatorFilter = (
  id: string,
  op: string,
) => void;

export type UseLocalStorage = [
  value: LocalStorage,
  setValue: Dispatch<SetStateAction<LocalStorage>>,
];

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
    if (
      Object.entries(urlParams).some(
        ([k, v]) => initialValue?.[k as keyof LocalStorage] !== v,
      )
    ) {
      window.history.replaceState(null, '', `?${effectiveParams.toString()}`);
    } else {
      window.history.replaceState(null, '', window.location.pathname);
    }
  }
};

const useLocalStorage = (
  key: string,
  initialValue?: LocalStorage,
  ignoreUri?: boolean,
): UseLocalStorage => {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<LocalStorage>(() => {
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
      // Need to clear the local storage ?
      if (!R.equals(removeEmptyFields(value), value)) {
        const initialState = removeEmptyFields(value);
        window.localStorage.setItem(key, JSON.stringify(initialState));
        return initialState;
      }
      // Values from uri must be prioritized on initial loading
      // Localstorage must be rewritten to ensure consistency
      if (isNotEmptyField(finalParams)) {
        const initialState = { ...value, ...finalParams };
        window.localStorage.setItem(key, JSON.stringify(initialState));
        return initialState;
      }
      return value;
    } catch (error) {
      // If error also return initialValue
      throw Error('Error while initializing values in local storage');
    }
  });
  // Return a wrapped version of useState's setter function that ...
  // ... persists the new value to localStorage.
  const setValue = (
    value: LocalStorage | ((val: LocalStorage) => LocalStorage),
  ) => {
    try {
      // Allow value to be a function so we have same API as useState
      let valueToStore = value instanceof Function ? value(storedValue) : value;
      valueToStore = removeEmptyFields(valueToStore);
      // Save state
      setStoredValue(valueToStore);
      // Save to local storage + re-align uri if needed
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
        if (!ignoreUri) {
          setStoredValueToHistory(initialValue, valueToStore);
        }
      }
    } catch (error) {
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
  const paginationOptions = localStorageToPaginationOptions(viewStorage);
  const { filterKeysSchema } = useAuth().schema;
  const helpers: UseLocalStorageHelpers = {
    handleSearch: (value: string) => setValue((c) => ({ ...c, searchTerm: value })),
    handleRemoveFilterById: (id: string) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        setValue((c) => ({
          ...c,
          filters: handleRemoveFilterUtil({ filters, id }),
          latestAddFilterId: undefined,
        }));
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
              setValue((c) => ({
                ...c,
                filters: newBaseFilters,
              }));
            } else { // values is empty: remove the filter with key=k and operator=op
              const newBaseFilters = {
                ...viewStorage.filters,
                filters: [
                  ...viewStorage.filters.filters
                    .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
                ],
              };
              setValue((c) => ({
                ...c,
                filters: newBaseFilters,
              }));
            }
          }
        } else {
          const newBaseFilters = {
            ...viewStorage.filters,
            filters: viewStorage.filters.filters
              .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
          };
          setValue((c) => ({
            ...c,
            filters: newBaseFilters,
          }));
        }
      }
    },
    handleSort: (field: string, order: boolean) => setValue((c) => ({
      ...c,
      sortBy: field,
      orderAsc: order,
    })),
    handleAddProperty: (field: string, value: unknown) => {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore
      if (!R.equals(viewStorage[field], value)) {
        setValue((c) => ({ ...c, [field]: value }));
      }
    },
    handleAddFilter: (
      k: string,
      id: string,
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
        setValue((c) => ({
          ...c,
          filters: newBaseFilters,
        }));
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
        setValue((c) => ({
          ...c,
          filters: newBaseFilters,
        }));
      }
    },
    handleRemoveRepresentationFilter: (
      id: string,
      value: string,
    ) => {
      if (viewStorage?.filters) {
        const filters = viewStorage?.filters;
        setValue((c) => ({
          ...c,
          filters: handleRemoveRepresentationFilterUtil({ filters, id, value }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleAddRepresentationFilter: (id: string, value: string) => {
      if (value === null) { // handle clicking on 'no label' in entities list
        const findCorrespondingFilter = viewStorage.filters?.filters.find((f) => id === f.id);
        if (findCorrespondingFilter && ['objectLabel'].includes(findCorrespondingFilter.key)) {
          if (viewStorage.filters) {
            const { filters } = viewStorage;
            setValue((c) => ({
              ...c,
              filters: handleChangeOperatorFiltersUtil({
                filters,
                id,
                operator: findCorrespondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
              }),
              latestAddFilterId: id,
            }));
          }
        }
      } else if (viewStorage?.filters) {
        const { filters } = viewStorage;
        setValue((c) => ({
          ...c,
          filters: handleAddRepresentationFilterUtil({ filters, id, value }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => {
      const filters = viewStorage?.filters;
      if (!filters) {
        return;
      }
      if (oldValue && newValue) {
        setValue((c) => ({
          ...c,
          filters: handleChangeRepresentationFilterUtil({ filters, id, oldValue, newValue }),
          latestAddFilterId: undefined,
        }));
      } else if (oldValue) {
        setValue((c) => ({
          ...c,
          filters: handleRemoveRepresentationFilterUtil({ filters, id, value: oldValue }),
          latestAddFilterId: undefined,
        }));
      } else if (newValue) {
        setValue((c) => ({
          ...c,
          filters: handleAddRepresentationFilterUtil({ filters, id, value: newValue }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleAddSingleValueFilter: (id: string, valueId?: string) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        setValue((c) => ({
          ...c,
          filters: handleAddSingleValueFilterUtil({ filters, id, valueId }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleSwitchFilter: (
      k: string,
      id: string,
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
        setValue((c) => ({
          ...c,
          filters: newBaseFilters,
        }));
      } else {
        const newBaseFilters = viewStorage.filters ? {
          ...viewStorage.filters,
          filters: [...viewStorage.filters.filters, newFilterElement], // set new filter
        } : {
          mode: 'and',
          filterGroups: [],
          filters: [newFilterElement],
        };
        setValue((c) => ({
          ...c,
          filters: newBaseFilters,
        }));
      }
    },
    handleSwitchGlobalMode: () => {
      if (viewStorage.filters) {
        const newBaseFilters = {
          ...viewStorage.filters,
          mode: viewStorage.filters.mode === 'and' ? 'or' : 'and',
        };
        setValue((c) => ({
          ...c,
          filters: newBaseFilters,
          latestAddFilterId: undefined,
        }));
      }
    },
    handleSwitchLocalMode: (filter: Filter) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        setValue((c) => ({
          ...c,
          filters: handleSwitchLocalModeUtil({ filters, filter }),
          latestAddFilterId: undefined,
        }));
      }
    },
    handleChangeView: (value: string) => setValue((c) => ({ ...c, filters: initialValue.filters ?? emptyFilterGroup, searchTerm: initialValue.searchTerm ?? '', view: value })),
    handleToggleExports: () => setValue((c) => ({ ...c, openExports: !c.openExports })),
    handleSetNumberOfElements: (nbElements: { number?: number | string; symbol?: string; original?: number; }) => {
      if (!R.equals(nbElements, viewStorage.numberOfElements)) {
        setValue((c) => {
          const { number, symbol, original } = nbElements;
          return {
            ...c,
            numberOfElements: {
              ...c.numberOfElements,
              ...(number ? { number } : { number: 0 }),
              ...(symbol ? { symbol } : { symbol: '' }),
              ...(original ? { original } : { original: 0 }),
            },
          };
        });
      }
    },
    handleToggleTypes: (type: string) => {
      if (viewStorage.types?.includes(type)) {
        const newTypes = viewStorage.types.filter((t) => t !== type);
        setValue((c) => ({ ...c, types: newTypes }));
      } else {
        const newTypes = viewStorage.types ? [...viewStorage.types, type] : [type];
        setValue((c) => ({ ...c, types: newTypes }));
      }
    },
    handleClearTypes: () => {
      setValue((c) => ({ ...c, types: [] }));
    },
    handleClearAllFilters: () => {
      setValue((c) => ({ ...c, filters: initialValue.filters ?? emptyFilterGroup, searchTerm: initialValue.searchTerm ?? '' }));
    },
    handleAddFilterWithEmptyValue: (filter: Filter) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        setValue((c) => ({
          ...c,
          filters: handleAddFilterWithEmptyValueUtil({ filters, filter }),
          latestAddFilterId: filter.id,
        }));
      }
    },
    handleChangeOperatorFilters: (id: string, operator: string) => {
      if (viewStorage?.filters) {
        const { filters } = viewStorage;
        setValue((c) => ({
          ...c,
          filters: handleChangeOperatorFiltersUtil({ filters, id, operator }),
          latestAddFilterId: undefined,
        }));
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
