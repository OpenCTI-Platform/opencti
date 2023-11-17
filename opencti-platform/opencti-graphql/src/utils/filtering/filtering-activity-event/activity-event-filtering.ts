import type { Filter, FilterGroup } from '../../../generated/graphql';
import type { ActivityStreamEvent } from '../../../manager/activityListener';
import { FILTER_WITH_EVENTS_KEY_TESTERS_MAP } from './activity-event-testers';
import { testFilterGroup } from '../boolean-logic-engine';

//----------------------------------------------------------------------------------------------------------------------

// Validate Filter in case of comparison against an event
export const validateFilterForActivityEventMatch = (filter: Filter) => {
  if (!Array.isArray(filter.key)) {
    throw Error(`The provided filter key is not an array - got ${JSON.stringify(filter.key)}`);
  }
  if (filter.key.length !== 1) {
    throw Error(`Activity Stream Event filtering can only be executed on a unique filter key - got ${JSON.stringify(filter.key)}`);
  }
  if (FILTER_WITH_EVENTS_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
    throw Error(`Activity Stream Event filtering is not compatible with the provided filter key ${JSON.stringify(filter.key)} - available filter keys: ${JSON.stringify(Object.keys(FILTER_WITH_EVENTS_KEY_TESTERS_MAP))}`);
  }
};

export const validateFilterGroupForActivityEventMatch = (filterGroup: FilterGroup) => {
  if (!filterGroup?.filterGroups || !filterGroup?.filters) {
    throw Error('Unrecognized filter format; expecting FilterGroup');
  }
  filterGroup.filters.forEach((f) => validateFilterForActivityEventMatch(f));
  filterGroup.filterGroups.forEach((fg) => validateFilterGroupForActivityEventMatch(fg));
};

//----------------------------------------------------------------------------------------------------------------------

/**
 * Tells if a given Activity Stream Event matches the given filter
 * @param event
 * @param filterGroup
 */
export const isActivityEventMatchFilterGroup = async (
  event: ActivityStreamEvent,
  filterGroup: FilterGroup,
) : Promise<boolean> => {
  // check the filter is well formed and compatible for event matching
  validateFilterGroupForActivityEventMatch(filterGroup);
  // then call our boolean engine on the filter group using the event testers
  return testFilterGroup(event, filterGroup, FILTER_WITH_EVENTS_KEY_TESTERS_MAP);
};
