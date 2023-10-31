//----------------------------------------------------------------------------------------------------------
// TYPES: TODO: remove them from here and use the one defined for #2686

import { INDICATOR_FILTER, } from '../filtering';
import { getStixTesterFromFilterKey } from './stix-testers';
import { testFilterGroup } from './boolean-logic-engine';
import type { Filter, FilterGroup } from './filter-group';

// TODO: changed by Cathia, to integrate properly with her
const LABEL_FILTER = 'objectLabel';

//----------------------------------------------------------------------------------------------------------

/**
 * Resolve some of the values (recursively) inside the filter group
 * so that testers work properly on either the unresolved ids or the resolved values (from the ids)
 * To date, we need to use the resolved values instead of ids for: Indicators, labels.
 * @param filter
 */
export const adaptFilter = (filter: Filter): Filter => {
  if (filter.key[0] === INDICATOR_FILTER || filter.key[0] === LABEL_FILTER) {
    return {
      ...filter,
      values: filter.values.map((id) => id) // TODO: resolve into values
    };
  }
  return filter;
};

export const adaptFilterGroup = (filterGroup: FilterGroup): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => adaptFilter(f)),
    filterGroups: filterGroup.filterGroups.map((fg) => adaptFilterGroup(fg))
  };
};

export const isStixMatchFilterGroup = (stix: any, filterGroup: FilterGroup) : boolean => {
  // First adapt the filter to resolve some of the ids as we search their corresponding values
  const resolvedFilterGroup = adaptFilterGroup(filterGroup);

  // then call our boolean engine on the filter group using the stix testers
  return testFilterGroup(stix, resolvedFilterGroup, getStixTesterFromFilterKey);
};
