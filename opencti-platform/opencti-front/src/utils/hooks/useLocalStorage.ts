import { Dispatch, SetStateAction, SyntheticEvent, useState } from 'react';
import * as R from 'ramda';
import { isEmptyField, isNotEmptyField, removeEmptyFields } from '../utils';
import {
  Filters,
  OrderMode,
  PaginationOptions,
} from '../../components/list_lines';
import { BackendFilters, isUniqFilter } from '../filters/filtersUtils';
import { convertFilters } from '../ListParameters';

export interface LocalStorage {
  numberOfElements?: {
    number: number | string;
    symbol: string;
    original?: number;
  };
  filters?: Filters;
  id?: string;
  searchTerm?: string;
  category?: string;
  toId?: string;
  sortBy?: string;
  orderAsc?: boolean;
  openExports?: boolean;
  count?: number;
  types?: string[];
  view?: string;
  zoom?: Record<string, unknown>;
  redirectionMode?: string;
  selectAll?: boolean;
  selectedElements?: Record<string, unknown>;
  deSelectedElements?: Record<string, unknown>;
}

export interface UseLocalStorageHelpers {
  handleSearch: (value: string) => void;
  handleRemoveFilter: (key: string) => void;
  handleSort: (field: string, order: boolean) => void;
  handleAddFilter: HandleAddFilter;
  handleToggleExports: () => void;
  handleSetNumberOfElements: (value: {
    number?: number | string;
    symbol?: string;
    original?: number;
  }) => void;
  handleSetRedirectionMode: (value: string) => void;
  handleAddProperty: (field: string, value: unknown) => void;
}

const localStorageToPaginationOptions = ({
  searchTerm,
  filters,
  sortBy,
  orderAsc,
  ...props
}: LocalStorage, additionalFilters?: BackendFilters): PaginationOptions => {
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
  // Rebuild some pagination options
  const basePagination: PaginationOptions = { ...localOptions };
  if (searchTerm) {
    basePagination.search = searchTerm;
  }
  if (orderAsc || sortBy) {
    basePagination.orderMode = orderAsc ? OrderMode.asc : OrderMode.desc;
    basePagination.orderBy = sortBy;
  }
  if (filters) {
    const paginationFilters = convertFilters(filters).concat(additionalFilters ?? []);
    basePagination.filters = paginationFilters as unknown as Filters;
  }
  return basePagination;
};

export type HandleAddFilter = (
  k: string,
  id: string,
  value: Record<string, unknown> | string,
  event: SyntheticEvent
) => void;

export type UseLocalStorage = [
  value: LocalStorage,
  setValue: Dispatch<SetStateAction<LocalStorage>>,
];

const buildParamsFromHistory = (params: LocalStorage) => removeEmptyFields({
  filters:
      params.filters && Object.keys(params.filters).length > 0
        ? JSON.stringify(params.filters)
        : undefined,
  zoom: JSON.stringify(params.zoom),
  searchTerm: params.searchTerm,
  sortBy: params.sortBy,
  orderAsc: params.orderAsc,
});

const searchParamsToStorage = (searchObject: URLSearchParams) => {
  const zoom = searchObject.get('zoom');
  const filters = searchObject.get('filters');
  return removeEmptyFields({
    filters: filters ? JSON.parse(filters) : undefined,
    zoom: zoom ? JSON.parse(zoom) : undefined,
    searchTerm: searchObject.get('searchTerm')
      ? searchObject.get('searchTerm')
      : undefined,
    sortBy: searchObject.get('sortBy'),
    orderAsc: searchObject.get('orderAsc')
      ? searchObject.get('orderAsc') === 'true'
      : undefined,
  });
};

const setStoredValueToHistory = (initialValue: LocalStorage, valueToStore: LocalStorage) => {
  const searchParams = new URLSearchParams(window.location.search);
  const finalParams = searchParamsToStorage(searchParams);
  const urlParams = buildParamsFromHistory(valueToStore);
  if (!R.equals(urlParams, buildParamsFromHistory(finalParams))) {
    const effectiveParams = new URLSearchParams(urlParams);
    if (Object.entries(urlParams).some(([k, v]) => initialValue[k as keyof LocalStorage] !== v)) {
      window.history.replaceState(null, '', `?${effectiveParams.toString()}`);
    } else {
      window.history.replaceState(null, '', window.location.pathname);
    }
  }
};

const useLocalStorage = (key: string, initialValue: LocalStorage): UseLocalStorage => {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<LocalStorage>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    try {
      const searchParams = new URLSearchParams(window.location.search);
      const finalParams = searchParamsToStorage(searchParams);
      // Get from local storage by key
      const item = window.localStorage.getItem(key);
      // Parse stored json or if none return initialValue
      let value: LocalStorage = item ? JSON.parse(item) : null;
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
      return value;
    } catch (error) {
      // If error also return initialValue
      throw Error('Error while initializing values in local storage');
    }
  });
  // Return a wrapped version of useState's setter function that ...
  // ... persists the new value to localStorage.
  const setValue = (value: LocalStorage | ((val: LocalStorage) => LocalStorage)) => {
    try {
      // Allow value to be a function so we have same API as useState
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      // Save state
      setStoredValue(valueToStore);
      // Save to local storage + re-align uri if needed
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
        setStoredValueToHistory(initialValue, valueToStore);
      }
    } catch (error) {
      // A more advanced implementation would handle the error case
      throw Error('Error while setting values in local storage');
    }
  };
  // re-align uri if needed
  setStoredValueToHistory(initialValue, storedValue);
  return [storedValue, setValue];
};

export type PaginationLocalStorage<U = Record<string, unknown>> = {
  viewStorage: LocalStorage;
  helpers: UseLocalStorageHelpers;
  paginationOptions: U;
};

export const usePaginationLocalStorage = <U>(
  key: string,
  initialValue: LocalStorage,
  additionalFilters?: BackendFilters,
): PaginationLocalStorage<U> => {
  const [viewStorage, setValue] = useLocalStorage(key, initialValue);
  const paginationOptions = localStorageToPaginationOptions(
    { count: 25, ...viewStorage },
    additionalFilters,
  );

  const helpers = {
    handleSearch: (value: string) => setValue((c) => ({ ...c, searchTerm: value })),
    handleRemoveFilter: (value: string) => setValue((c) => ({
      ...c,
      filters: R.dissoc<Filters, string>(value, c.filters as Filters),
    })),
    handleSort: (field: string, order: boolean) => setValue((c) => ({
      ...c,
      sortBy: field,
      orderAsc: order,
    })),
    handleAddProperty: (field: string, value: unknown) => {
      setValue((c) => ({ ...c, [field]: value }));
    },
    handleAddFilter: (
      k: string,
      id: string,
      value: Record<string, unknown> | string,
      event: SyntheticEvent,
    ) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      if ((viewStorage?.filters?.[k]?.length ?? 0) > 0) {
        setValue((c) => ({
          ...c,
          filters: {
            ...c.filters,
            [k]: isUniqFilter(k)
              ? [{ id, value }]
              : [
                ...(c.filters?.[k].filter((f) => f.id !== id) ?? []),
                {
                  id,
                  value,
                },
              ],
          },
        }));
      } else {
        setValue((c) => ({
          ...c,
          filters: R.assoc(k, [{ id, value }], c.filters),
        }));
      }
    },
    handleToggleExports: () => setValue((c) => ({ ...c, openExports: !c.openExports })),
    handleSetNumberOfElements: (nbElements: {
      number?: number | string;
      symbol?: string;
      original?: number;
    }) => {
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
    handleSetRedirectionMode: (value: string) => {
      setValue((c) => ({ ...c, redirectionMode: value }));
    },
  };

  return {
    viewStorage,
    helpers,
    paginationOptions: paginationOptions as U,
  };
};

export default useLocalStorage;
