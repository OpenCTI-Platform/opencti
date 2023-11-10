import { UseLocalStorageHelpers } from '../hooks/useLocalStorage';

let filterHelpers: UseLocalStorageHelpers | undefined;

export const setFilterHelpers = (helpers: UseLocalStorageHelpers) => {
  filterHelpers = helpers;
};

export const getFilterHelpers = () => {
  return filterHelpers;
};
