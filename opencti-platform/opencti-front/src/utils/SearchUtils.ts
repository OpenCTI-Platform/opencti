import { NavigateFunction } from 'react-router/dist/lib/hooks';

export const handleSearchByKeyword = (searchKeyword: string, searchScope: string, navigate: NavigateFunction) => {
  const encodeKey = encodeURIComponent(searchKeyword);
  navigate(`/dashboard/search/${searchScope}/${encodeKey}?sortBy=_score&orderAsc=false`);
};

export const handleSearchByFilter = (
  searchScope: string,
  navigate: NavigateFunction,
  stringFilters?: string | null,
) => {
  const filtersURI = stringFilters ? `?filters=${encodeURIComponent(stringFilters)}` : '';
  const link = `/dashboard/search/${searchScope}/${filtersURI}`;
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
