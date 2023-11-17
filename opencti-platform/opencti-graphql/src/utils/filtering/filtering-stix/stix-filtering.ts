import { FILTER_KEY_TESTERS_MAP } from './stix-testers';
import { testFilterGroup } from '../boolean-logic-engine';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../../access';
import type { AuthContext, AuthUser } from '../../../types/user';
import { getEntitiesMapFromCache } from '../../../database/cache';
import type { StixObject } from '../../../types/stix-common';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../../schema/stixDomainObject';
import type { Filter, FilterGroup } from '../../../generated/graphql';
import type { FilterResolutionMap } from '../filtering-resolution';
import { buildResolutionMapForFilterGroup, resolveFilterGroup } from '../filtering-resolution';

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
