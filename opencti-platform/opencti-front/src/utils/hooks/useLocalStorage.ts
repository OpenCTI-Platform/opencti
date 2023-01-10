import { Dispatch, SetStateAction, SyntheticEvent, useState } from 'react';
import * as R from 'ramda';
import { isEmptyField, removeEmptyFields } from '../utils';
import {
  Filters,
  OrderMode,
  PaginationOptions,
} from '../../components/list_lines';
import { isUniqFilter } from '../filters/filtersUtils';
import { convertFilters } from '../ListParameters';
import { DataComponentsLinesPaginationQuery$variables } from '../../private/components/techniques/data_components/__generated__/DataComponentsLinesPaginationQuery.graphql';

export interface LocalStorage {
  numberOfElements?: {
    number: number | string;
    symbol: string;
    original?: number;
  };
  filters?: Filters;
  searchTerm?: string;
  sortBy?: string;
  orderAsc?: boolean;
  openExports?: boolean;
  count?: number;
  types?: string[];
  view?: string;
  zoom?: Record<string, unknown>;
  additionnalFilters?: { key: string, values: string[], operator: string, filterMode: string }[] | undefined;
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
}

export const localStorageToPaginationOptions = <U>({
  searchTerm,
  filters,
  sortBy,
  orderAsc,
  additionnalFilters,
  ...props
}: LocalStorage & Omit<U, 'filters'>): unknown extends U
    ? PaginationOptions
    : U => {
  // Remove only display options, not query linked
  const localOptions = { ...props };
  delete localOptions.openExports;
  delete localOptions.numberOfElements;
  delete localOptions.view;
  delete localOptions.zoom;
  let finalFilters = filters ? convertFilters(filters) : undefined;
  if (finalFilters && additionnalFilters) {
    finalFilters = (finalFilters as { key: string, values: string[], operator: string, filterMode: string }[]).concat(additionnalFilters);
  }
  return {
    ...localOptions,
    search: searchTerm,
    orderMode: orderAsc ? OrderMode.asc : OrderMode.desc,
    orderBy: sortBy,
    filters: finalFilters,
  } as unknown extends U ? PaginationOptions : U;
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
  helpers: UseLocalStorageHelpers,
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

const useLocalStorage = (
  key: string,
  initialValue: LocalStorage,
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
      let value: LocalStorage = item ? JSON.parse(item) : null;
      if (isEmptyField(value)) {
        value = initialValue;
      }
      return Array.from(searchParams.values()).length > 0
        ? { ...value, ...finalParams }
        : value;
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
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      // Save state
      setStoredValue(valueToStore);
      // Save to local storage
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));

        const searchParams = new URLSearchParams(window.location.search);
        const finalParams = searchParamsToStorage(searchParams);
        const urlParams = buildParamsFromHistory(valueToStore);

        if (!R.equals(urlParams, buildParamsFromHistory(finalParams))) {
          const effectiveParams = new URLSearchParams(urlParams);
          if (
            Object.entries(urlParams).some(
              ([k, v]) => initialValue[k as keyof LocalStorage] !== v,
            )
          ) {
            window.history.replaceState(
              null,
              '',
              `?${effectiveParams.toString()}`,
            );
          } else {
            window.history.replaceState(null, '', window.location.pathname);
          }
        }
      }
    } catch (error) {
      // A more advanced implementation would handle the error case
      throw Error('Error while setting values in local storage');
    }
  };

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
      if ((storedValue?.filters?.[k]?.length ?? 0) > 0) {
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
      if (!R.equals(nbElements, storedValue.numberOfElements)) {
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

  return [storedValue, setValue, helpers];
};

type PaginationLocalStorage<U> = {
  viewStorage: LocalStorage;
  helpers: UseLocalStorageHelpers;
  paginationOptions: U;
};

export const usePaginationLocalStorage = <U>(
  key: string,
  initialValue: LocalStorage,
): PaginationLocalStorage<U> => {
  const [viewStorage, , helpers] = useLocalStorage(key, initialValue);
  const paginationOptions = localStorageToPaginationOptions<DataComponentsLinesPaginationQuery$variables>(
    {
      ...viewStorage,
      count: 25,
    },
  );
  return {
    viewStorage,
    helpers,
    paginationOptions: paginationOptions as U,
  };
};

export default useLocalStorage;
