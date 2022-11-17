import React, { Dispatch, SetStateAction, useState } from 'react';
import * as R from 'ramda';
import { isEmptyField } from '../utils';
import { Filters, OrderMode, PaginationOptions } from '../../components/list_lines';
import { isUniqFilter } from '../../private/components/common/lists/Filters';

export interface LocalStorage {
  numberOfElements?: { number: number, symbol: string },
  filters?: Filters,
  searchTerm?: string,
  sortBy?: string,
  orderAsc?: boolean,
  openExports?: boolean,
  count?: number
}

export const localStorageToPaginationOptions = <U>({
  searchTerm,
  filters,
  sortBy,
  orderAsc,
  ...props
}: LocalStorage & Omit<U, 'filters'>): unknown extends U ? PaginationOptions : U => {
  // OpenExports and NumberOfElements are only display options, not query linked
  const { openExports: _, numberOfElements: __, ...localOptions } = props;
  return ({
    ...localOptions,
    search: searchTerm,
    orderMode: orderAsc ? OrderMode.asc : OrderMode.desc,
    orderBy: sortBy,
    filters,
  }) as unknown extends U ? PaginationOptions : U;
};

export type UseLocalStorage = [value: LocalStorage,
  setValue: Dispatch<SetStateAction<LocalStorage>>,
  helpers: {
    handleSearch: (value: string) => void,
    handleRemoveFilter: (key: string) => void,
    handleSort: (field: string, order: boolean) => void
    handleAddFilter: (k: string, id: string, value: Record<string, unknown>, event: React.KeyboardEvent) => void
    handleToggleExports: () => void,
    handleSetNumberOfElements: (value: { number?: number, symbol?: string }) => void,
  },
];

const useLocalStorage = (key: string, initialValue: LocalStorage): UseLocalStorage => {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<LocalStorage>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    try {
      // Get from local storage by key
      const item = window.localStorage.getItem(key);
      // Parse stored json or if none return initialValue
      const value: LocalStorage = item ? JSON.parse(item) : null;
      return isEmptyField<LocalStorage>(value) ? initialValue : value;
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
      // Save to local storage
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
      }
    } catch (error) {
      // A more advanced implementation would handle the error case
      throw Error('Error while setting values in local storage');
    }
  };

  const helpers = {
    handleSearch: (value: string) => setValue((c) => ({ ...c, searchTerm: value })),
    handleRemoveFilter: (value: string) => setValue((c) => ({ ...c, filters: R.dissoc<Filters, string>(value, c.filters as Filters) })),
    handleSort: (field: string, order: boolean) => setValue((c) => ({
      ...c,
      sortBy: field,
      orderAsc: order,
    })),
    handleAddFilter: (k: string, id: string, value: Record<string, unknown>, event: React.KeyboardEvent) => {
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
        setValue((c) => ({ ...c, filters: R.assoc(k, [{ id, value }], c.filters) }));
      }
    },
    handleToggleExports: () => setValue((c) => ({ ...c, openExports: !c.openExports })),
    handleSetNumberOfElements: ({ number, symbol }: { number?: number, symbol?: string }) => setValue((c) => ({
      ...c,
      numberOfElements: {
        ...c.numberOfElements,
        ...(number ? { number } : { number: 0 }),
        ...(symbol ? { symbol } : { symbol: '' }),
      },
    })),
  };

  return [storedValue, setValue, helpers];
};

export default useLocalStorage;
