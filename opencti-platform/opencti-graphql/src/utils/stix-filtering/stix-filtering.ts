import {
  ASSIGNEE_FILTER,
  CREATED_BY_FILTER,
  INDICATOR_FILTER,
  LABEL_FILTER,
  MARKING_FILTER,
  OBJECT_CONTAINS_FILTER,
  PARTICIPANT_FILTER,
  RELATION_FROM_FILTER,
  RELATION_TO_FILTER,
} from '../filtering';
import { FILTER_KEY_TESTERS_MAP } from './stix-testers';
import { testFilterGroup } from './boolean-logic-engine';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../access';
import type { AuthContext, AuthUser } from '../../types/user';
import { getEntitiesMapFromCache } from '../../database/cache';
import type { StixObject } from '../../types/stix-common';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../schema/stixDomainObject';
import type { Filter, FilterGroup } from '../../generated/graphql';
import type { ActivityStreamEvent } from '../../manager/activityListener';
import { FILTER_WITH_EVENTS_KEY_TESTERS_MAP } from './event-testers';

//----------------------------------------------------------------------------------------------------------------------

/**
 * Pass through all individual filters and throws an error if it cannot be handled properly.
 * This is very aggressive but will allow us to detect rapidly any corner-case.
 */
export const validateFilterForStixMatch = (filter: Filter) => {
  if (!Array.isArray(filter.key)) {
    throw Error(`The provided filter key is not an array - got ${JSON.stringify(filter.key)}`);
  }
  if (filter.key.length !== 1) {
    throw Error(`Stix filtering can only be executed on a unique filter key - got ${JSON.stringify(filter.key)}`);
  }
  if (FILTER_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
    throw Error(`Stix filtering is not compatible with the provided filter key ${JSON.stringify(filter.key)} - available filter keys: ${JSON.stringify(Object.keys(FILTER_KEY_TESTERS_MAP))}`);
  }
};

/**
 * Recursively call validateFilter inside a FilterGroup
 */
export const validateFilterGroupForStixMatch = (filterGroup: FilterGroup) => {
  if (!filterGroup?.filterGroups || !filterGroup?.filters) {
    throw Error('Unrecognized filter format; expecting FilterGroup');
  }
  filterGroup.filters.forEach((f) => validateFilterForStixMatch(f));
  filterGroup.filterGroups.forEach((fg) => validateFilterGroupForStixMatch(fg));
};

// Validate Filter in case of comparison against an event
export const validateFilterForEventMatch = (filter: Filter) => {
  if (filter.key.length !== 1) {
    throw Error(`Activity Stream Event filtering can only be executed on a unique filter key - got ${JSON.stringify(filter.key)}`);
  }
  if (FILTER_WITH_EVENTS_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
    throw Error(`Activity Stream Event filtering is not compatible with the provided filter key ${JSON.stringify(filter.key)} - available filter keys: ${JSON.stringify(Object.keys(FILTER_WITH_EVENTS_KEY_TESTERS_MAP))}`);
  }
};

export const validateFilterGroupForEventMatch = (filterGroup: FilterGroup) => {
  if (!filterGroup?.filterGroups || !filterGroup?.filters) {
    throw Error('Unrecognized filter format; expecting FilterGroup');
  }
  filterGroup.filters.forEach((f) => validateFilterForEventMatch(f));
  filterGroup.filterGroups.forEach((fg) => validateFilterGroupForEventMatch(fg));
};

//----------------------------------------------------------------------------------------------------------------------

/**
 * Resolve some of the filter values according to a resolution map.
 * This concerns attributes that are not directly compared with a stix attribute due to modelization differences.
 * For instance, labels are entities internally, and filter.values would contain these entities ids.
 * In Stix, the labels are stored in plain text: we need to replace the ids in filter.values with their resolution.
 */
export const resolveFilter = (filter: Filter, resolutionMap: FilterResolutionMap): Filter => {
  const newFilterValues: string [] = [];
  filter.values.forEach((v) => {
    const resolution = resolutionMap.get(v);
    if (resolution) {
      newFilterValues.push(resolution);
    } else {
      newFilterValues.push(v);
    }
  });

  return {
    ...filter,
    values: newFilterValues
  };
};

/**
 * Recursively call resolveFilter inside a filter group
 */
export const resolveFilterGroup = (filterGroup: FilterGroup, resolutionMap: FilterResolutionMap): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => resolveFilter(f, resolutionMap)),
    filterGroups: filterGroup.filterGroups.map((fg) => resolveFilterGroup(fg, resolutionMap))
  };
};

//----------------------------------------------------------------------------------------------------------------------

type FilterResolutionMap = Map<string, string>;

// We use '.' for compound paths
const RESOLUTION_MAP_PATHS: Record<string, string> = {
  [ASSIGNEE_FILTER]: 'id', // assignee --> resolve with the standard id (which is the stix.id)
  [CREATED_BY_FILTER]: 'id', // created by --> resolve with the standard id (which is the stix.id)
  [LABEL_FILTER]: 'value', // labels --> resolve id to stix.name
  [INDICATOR_FILTER]: 'type', // indicator types --> resolve id to stix.type
  [MARKING_FILTER]: 'id', // marking --> resolve id to standard id (which is the stix.id)
  [OBJECT_CONTAINS_FILTER]: 'id',
  [PARTICIPANT_FILTER]: 'id', // participant --> resolve with the standard id (which is the stix.id)
  [RELATION_FROM_FILTER]: 'id',
  [RELATION_TO_FILTER]: 'id',
};

/**
 * Build a resolution map thanks to the cache
 */
const buildResolutionMapForFilter = async (context: AuthContext, user: AuthUser, mutableMap: FilterResolutionMap, filter: Filter, cache: Map<string, StixObject>) => {
  if (Object.keys(RESOLUTION_MAP_PATHS).includes(filter.key[0])) {
    for (let index = 0; index < filter.values.length; index += 1) {
      const v = filter.values[index];
      // manipulating proper stix objects typing requires a lot of refactoring at this point (typeguards, etc)
      // like with isStixMatchFilterGroup, let's use any to describe our stix objects in cache
      const cachedObject = cache.get(v) as any;
      const path = RESOLUTION_MAP_PATHS[filter.key[0]];
      if (cachedObject && path) {
        // some entities in cache might be restricted for this user or deleted
        if (!(await isUserCanAccessStixElement(context, user, cachedObject))) {
          // invalidate the filter value; it won't match ever, but we keep track of this invalidation for debug purposes
          mutableMap.set(v, '<restricted-or-deleted>');
        } else {
          // resolve according to path
          const cachedValue = cachedObject[path];
          if (typeof cachedValue === 'string') {
            mutableMap.set(v, cachedValue);
          }
        }
      }
    }
  }
};

/**
 * recursively call buildResolutionMapForFilter inside a filter group
 */
export const buildResolutionMapForFilterGroup = async (
  context: AuthContext,
  user: AuthUser,
  mutableMap: FilterResolutionMap,
  filterGroup: FilterGroup,
  cache: Map<string, StixObject>
) => {
  filterGroup.filters.forEach((f) => buildResolutionMapForFilter(context, user, mutableMap, f, cache));
  filterGroup.filterGroups.forEach((fg) => buildResolutionMapForFilterGroup(context, user, mutableMap, fg, cache));
};

/**
 * Utility function to resolve some values into what's comparable in stix format
 */
export const resolveFilterGroupValuesWithCache = async (context: AuthContext, user: AuthUser, filterGroup: FilterGroup) => {
  const resolutionMap = new Map<string, string>();
  const cache = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  await buildResolutionMapForFilterGroup(context, user, resolutionMap, filterGroup, cache);

  return resolveFilterGroup(filterGroup, resolutionMap);
};

//----------------------------------------------------------------------------------------------------------------------
// STIX MATCH

/**
 * Middleware function that allow us to make unit tests by mocking the resolution map.
 * This is necessary because the map is built thanks to the cache, not available in unit tests.
 */
export const isStixMatchFilterGroup_MockableForUnitTests = async (
  context: AuthContext,
  user: AuthUser,
  stix: any,
  filterGroup: FilterGroup,
  resolutionMap: FilterResolutionMap
) : Promise<boolean> => {
  // we are limited to certain filter keys right now, so better throw an explicit error if a key is not compatible
  // Note that similar check is done when saving a filter in stream, taxii, feed, or playbook node.
  // This check should thus not fail here, theoretically.
  validateFilterGroupForStixMatch(filterGroup);

  // first check: user access right (according to markings, organization, etc.)
  const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stix);
  if (!isUserHasAccessToElement) {
    return false;
  }

  const resolvedFilterGroup = resolveFilterGroup(filterGroup, resolutionMap);

  // then call our boolean engine on the filter group using the stix testers
  return testFilterGroup(stix, resolvedFilterGroup, FILTER_KEY_TESTERS_MAP);
};

/**
 * Tells if a stix object matches a filter group given a certain context.
 * The input filter group is a stored filter (streams, triggers, playbooks), the stix object comes from the raw stream.
 *
 * This function will first check the user access rights to the stix object, then resolve parts of the filter groups if necessary,
 * prior to actually comparing the filter values with the stix values.
 * @param context
 * @param user
 * @param stix stix object from the raw event stream
 * @param filterGroup
 * @throws {Error} on invalid filter keys
 */
export const isStixMatchFilterGroup = async (context: AuthContext, user: AuthUser, stix: any, filterGroup: FilterGroup) : Promise<boolean> => {
  // resolve some of the ids as we filter on their corresponding values or standard-id for instance
  // the provided map will contain replacements for filter values, if any necessary.
  const map = new Map<string, string>();
  // we use the entities stored in cache for the "Resolved-Filters" (all the entities used by the saved filters - stream, trigger, playbooks)
  // see cacheManager.ts:platformResolvedFilters
  const cache = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  await buildResolutionMapForFilterGroup(context, user, map, filterGroup, cache);

  return isStixMatchFilterGroup_MockableForUnitTests(context, user, stix, filterGroup, map);
};

//----------------------------------------------------------------------------------------------------------------------
// EVENT MATCH

/**
 * Tells if a given Activity Stream Event matches the given filter
 * @param event
 * @param filterGroup
 */
export const isEventMatchFilterGroup = async (
  event: ActivityStreamEvent,
  filterGroup: FilterGroup,
) : Promise<boolean> => {
  // check the filter is well formed and compatible for event matching
  validateFilterGroupForEventMatch(filterGroup);
  // then call our boolean engine on the filter group using the event testers
  return testFilterGroup(event, filterGroup, FILTER_WITH_EVENTS_KEY_TESTERS_MAP);
};
