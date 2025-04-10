import { NavigateFunction } from 'react-router-dom';
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
) => {
  const link = `/dashboard/search/${searchScope}/${encodeURIComponent(stringFilters ?? JSON.stringify(emptyFilterGroup))}/${searchKeyword}`;
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
