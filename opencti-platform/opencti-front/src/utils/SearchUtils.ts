import { NavigateFunction } from 'react-router/dist/lib/hooks';
import { UseLocalStorageHelpers } from './hooks/useLocalStorage';
import { emptyFilterGroup } from './filters/filtersUtils';

export const handleSearchByKeyword = (searchKeyword: string, searchScope: string, navigate: NavigateFunction) => {
  const encodeKey = encodeURIComponent(searchKeyword);
  navigate(`/dashboard/search/${searchScope}/${encodeKey}?sortBy=_score&orderAsc=false`);
};

export const handleSearchByFilter = (
  searchKeyword: string,
  searchScope: string,
  navigate: NavigateFunction,
  stringFilters?: string | null,
  helpers?: UseLocalStorageHelpers,
) => {
  helpers?.handleClearAllFilters();
  helpers?.handleSetFilters(stringFilters ? JSON.parse(stringFilters) : emptyFilterGroup);
  const filtersURI = stringFilters ? `?filters=${encodeURIComponent(stringFilters)}` : '';
  const link = `/dashboard/search/${searchScope}/${searchKeyword}${filtersURI}`;
  navigate(link);
};

export const decodeSearchKeyword = (searchKeyword: string) => {
  let searchTerm = '';
  try {
    searchTerm = decodeURIComponent(searchKeyword || '');
  } catch (e) {
    // Do nothing
  }
  return searchTerm;
};
