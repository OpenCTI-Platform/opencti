import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';

const getSavedFilterScopeFilter = (scopeKey: string): FilterGroup => ({
  mode: 'and',
  filters: [
    {
      mode: 'and',
      key: 'scope',
      values: [scopeKey],
    },
  ],
  filterGroups: [],
});

export default getSavedFilterScopeFilter;
