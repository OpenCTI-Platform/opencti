import * as R from 'ramda';
import { Dispatch, SetStateAction, SyntheticEvent, useState } from 'react';
import { Filters, OrderMode, PaginationOptions } from '../../components/list_lines';
import { BackendFilters, isUniqFilter } from '../filters/filtersUtils';
import { convertFilters } from '../ListParameters';
import { isEmptyField, isNotEmptyField, removeEmptyFields } from '../utils';

export interface MessageFromLocalStorage {
  id: string
  message: string
  activated: boolean
  dismissible: boolean
  updated_at: Date
  dismiss: boolean
  color: string
}

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
  messages?: MessageFromLocalStorage[]
  timeField?: string
  dashboard?: string
}

export interface UseLocalStorageHelpers {
  handleSearch: (value: string) => void;
  handleRemoveFilter: (key: string, id?: string) => void;
  handleSort: (field: string, order: boolean) => void;
  handleAddFilter: HandleAddFilter;
  handleSwitchFilter: HandleAddFilter;
  handleToggleExports: () => void;
  handleSetNumberOfElements: (value: {
    number?: number | string;
    symbol?: string;
    original?: number;
  }) => void;
  handleAddProperty: (field: string, value: unknown) => void;
  handleChangeView: (value: string) => void;
}

const localStorageToPaginationOptions = (
  { searchTerm, filters, sortBy, orderAsc, ...props }: LocalStorage,
  additionalFilters?: BackendFilters,
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
  // Rebuild some pagination options
  const basePagination: PaginationOptions = { ...localOptions };
  if (searchTerm) {
    basePagination.search = searchTerm;
  }
  if (orderAsc || sortBy) {
    basePagination.orderMode = orderAsc ? OrderMode.asc : OrderMode.desc;
    basePagination.orderBy = sortBy;
  }
  const paginationFilters: BackendFilters = [...(convertFilters(filters ?? {}) as unknown as BackendFilters), ...(additionalFilters ?? [])];
  basePagination.filters = paginationFilters.length > 0 ? paginationFilters : undefined;
  return basePagination;
};

export type HandleAddFilter = (
  k: string,
  id: string,
  value: Record<string, unknown> | string,
  event?: SyntheticEvent
) => void;

export type UseLocalStorage = [
  value: LocalStorage,
  setValue: Dispatch<SetStateAction<LocalStorage>>,
];

const buildParamsFromHistory = (params: LocalStorage) => {
  return removeEmptyFields({
    filters: params.filters && Object.keys(params.filters).length > 0 ? JSON.stringify(params.filters) : undefined,
    zoom: JSON.stringify(params.zoom),
    searchTerm: params.searchTerm,
    sortBy: params.sortBy,
    orderAsc: params.orderAsc,
    timeField: params.timeField,
    dashboard: params.dashboard,
    types: (params.types && params.types.length > 0) ? params.types.join(',') : undefined,
  });
};

const searchParamsToStorage = (searchObject: URLSearchParams) => {
  const zoom = searchObject.get('zoom');
  const filters = searchObject.get('filters');
  return removeEmptyFields({
    filters: filters ? JSON.parse(filters) : undefined,
    zoom: zoom ? JSON.parse(zoom) : undefined,
    searchTerm: searchObject.get('searchTerm') ? searchObject.get('searchTerm') : undefined,
    sortBy: searchObject.get('sortBy'),
    types: searchObject.get('types') ? searchObject.get('types')?.split(',') : undefined,
    orderAsc: searchObject.get('orderAsc') ? searchObject.get('orderAsc') === 'true' : undefined,
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
      Object.entries(urlParams)
        .some(([k, v]) => initialValue?.[k as keyof LocalStorage] !== v)
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
): UseLocalStorage => {
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
    handleRemoveFilter: (k: string, id?: string) => setValue((c) => {
      if (id) {
        const values = c.filters?.[k].filter((f) => f.id !== id);
        if (values && values.length > 0) {
          return {
            ...c,
            filters: {
              ...c.filters,
              [k]: values,
            },
          };
        }
        return {
          ...c,
          filters: R.dissoc<Filters, string>(k, c.filters as Filters),
        };
      }
      return {
        ...c,
        filters: R.dissoc<Filters, string>(k, c.filters as Filters),
      };
    }),
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
      value: Record<string, unknown> | string,
      event?: SyntheticEvent,
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
    handleSwitchFilter: (
      k: string,
      id: string,
      value: Record<string, unknown> | string,
      event?: SyntheticEvent,
    ) => {
      if (event) {
        event.stopPropagation();
        event.preventDefault();
      }
      setValue((c) => ({ ...c, filters: R.assoc(k, [{ id, value }], c.filters) }));
    },
    handleChangeView: (value: string) => setValue((c) => ({ ...c, view: value })),
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
  };

  return {
    viewStorage,
    helpers,
    paginationOptions: paginationOptions as U,
  };
};

export default useLocalStorage;
