import { Dispatch, SetStateAction, useState } from 'react';
import { isEmptyField } from '../utils';
import { Filters, OrderMode, PaginationOptions } from '../../components/list_lines';

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
  // eslint-disable-next-line @typescript-eslint/naming-convention
  const { openExports: _, numberOfElements: __, ...localOptions } = props;
  return ({
    ...localOptions,
    search: searchTerm,
    orderMode: orderAsc ? OrderMode.asc : OrderMode.desc,
    orderBy: sortBy,
    filters,
  }) as unknown extends U ? PaginationOptions : U;
};

const useLocalStorage = <T = LocalStorage>(key: string, initialValue: T): [value: T, setValue: Dispatch<SetStateAction<T>>] => {
  // State to store our value
  // Pass initial state function to useState so logic is only executed once
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    try {
      // Get from local storage by key
      const item = window.localStorage.getItem(key);
      // Parse stored json or if none return initialValue
      const value: T = item ? JSON.parse(item) : null;
      return isEmptyField<T>(value) ? initialValue : value;
    } catch (error) {
      // If error also return initialValue
      throw Error('Error while initializing values in local storage');
    }
  });
  // Return a wrapped version of useState's setter function that ...
  // ... persists the new value to localStorage.
  const setValue = (value: T | ((val: T) => T)) => {
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
  return [storedValue, setValue];
};

export default useLocalStorage;
