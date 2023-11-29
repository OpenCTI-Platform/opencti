export const handleSearchByKeyword = (searchKeyword, searchScope, history) => {
  if (searchKeyword.length > 0) {
    // With need to double encode because of react router.
    // Waiting for history 5.0 integrated to react router.
    const encodeKey = encodeURIComponent(encodeURIComponent(searchKeyword));
    history.push(`/dashboard/search/${searchScope}/${encodeKey}`);
  }
};

export const decodeSearchKeyword = (searchKeyword) => {
  let searchTerm = '';
  try {
    searchTerm = decodeURIComponent(searchKeyword || '');
  } catch (e) {
    // Do nothing
  }
  return searchTerm;
};
