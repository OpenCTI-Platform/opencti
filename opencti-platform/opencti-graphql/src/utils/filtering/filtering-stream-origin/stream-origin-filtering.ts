import type { Filter, FilterGroup } from '../../../generated/graphql';
import { testFilterGroup, type TesterFunction } from '../boolean-logic-engine';
import { UnsupportedError } from '../../../config/errors';
import { testMembersGroup, testMembersOrganization, testMembersUser } from '../filtering-activity-event/activity-event-testers';
import { MEMBERS_GROUP_FILTER, MEMBERS_ORGANIZATION_FILTER, MEMBERS_USER_FILTER } from '../filtering-constants';
import { isFilterGroupNotEmpty } from '../filtering-utils';

// Reuses the existing activity-event member testers; they read `event.origin.{user_id, group_ids, organization_ids}`,
// which matches the SSE event envelope shape.
const STREAM_ORIGIN_TESTERS_MAP: Record<string, TesterFunction> = {
  [MEMBERS_USER_FILTER]: testMembersUser,
  [MEMBERS_GROUP_FILTER]: testMembersGroup,
  [MEMBERS_ORGANIZATION_FILTER]: testMembersOrganization,
};

const validateFilterForStreamOriginMatch = (filter: Filter) => {
  if (!Array.isArray(filter.key) || filter.key.length !== 1) {
    throw UnsupportedError('Stream origin filtering can only be executed on a unique filter key', { key: JSON.stringify(filter.key) });
  }
  if (STREAM_ORIGIN_TESTERS_MAP[filter.key[0]] === undefined) {
    const availableFilters = JSON.stringify(Object.keys(STREAM_ORIGIN_TESTERS_MAP));
    throw UnsupportedError('Stream origin filtering is not compatible with the provided filter key', { key: JSON.stringify(filter.key), availableFilters });
  }
};

export const validateFilterGroupForStreamOriginMatch = (filterGroup: FilterGroup) => {
  if (!filterGroup?.filterGroups || !filterGroup?.filters) {
    throw UnsupportedError('Unrecognized filter format; expecting FilterGroup');
  }
  filterGroup.filters.forEach(validateFilterForStreamOriginMatch);
  filterGroup.filterGroups.forEach(validateFilterGroupForStreamOriginMatch);
};

/**
 * Tells whether a stream event matches the given origin filter group.
 * Empty / undefined filter group is considered as matching anything.
 */
export const isOriginMatchFilterGroup = (
  eventData: { origin?: { user_id?: string; group_ids?: string[]; organization_ids?: string[] } } | undefined,
  filterGroup?: FilterGroup,
): boolean => {
  if (!filterGroup || !isFilterGroupNotEmpty(filterGroup)) return true;
  // ensure origin is at least an empty object so testers can safely read its fields
  const target = { ...eventData, origin: eventData?.origin ?? {} };
  return testFilterGroup(target, filterGroup, STREAM_ORIGIN_TESTERS_MAP);
};
