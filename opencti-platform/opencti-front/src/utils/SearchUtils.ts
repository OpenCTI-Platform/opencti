import { NavigateFunction } from 'react-router/dist/lib/hooks';

export const handleSearchByKeyword = (searchKeyword: string, searchScope: string, navigate: NavigateFunction) => {
  const encodeKey = encodeURIComponent(searchKeyword);
  navigate(`/dashboard/search/${searchScope}/${encodeKey}?sortBy=_score&orderAsc=false`);
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
