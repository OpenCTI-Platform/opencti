import { FILTER_KEY_TESTERS_MAP } from './stix-testers';
import { testFilterGroup } from '../boolean-logic-engine';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../../access';
import type { AuthContext, AuthUser } from '../../../types/user';
import { getEntitiesMapFromCache } from '../../../database/cache';
import type { StixObject } from '../../../types/stix-2-1-common';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../../schema/stixDomainObject';
import type { Filter, FilterGroup } from '../../../generated/graphql';
import type { FilterResolutionMap } from '../filtering-resolution';
import { buildResolutionMapForFilterGroup, resolveFilterGroup } from '../filtering-resolution';
import { UnsupportedError } from '../../../config/errors';

//----------------------------------------------------------------------------------------------------------------------

/**
 * Pass through all individual filters and throws an error if it cannot be handled properly.
 * This is very aggressive but will allow us to detect rapidly any corner-case.
 */
export const validateFilterForStixMatch = (filter: Filter) => {
  if (!Array.isArray(filter.key)) {
    throw UnsupportedError('The provided filter key is not an array', { key: JSON.stringify(filter.key) });
  }
  if (filter.key.length !== 1) {
    throw UnsupportedError('Stix filtering can only be executed on a unique filter key', { key: JSON.stringify(filter.key) });
  }
  if (FILTER_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
    const availableFilters = JSON.stringify(Object.keys(FILTER_KEY_TESTERS_MAP));
    throw UnsupportedError('Stix filtering is not compatible with the provided filter key', { key: JSON.stringify(filter.key), availableFilters });
  }
};

/**
 * Recursively call validateFilter inside a FilterGroup
 */
export const validateFilterGroupForStixMatch = (filterGroup: FilterGroup) => {
  if (!filterGroup?.filterGroups || !filterGroup?.filters) {
    throw UnsupportedError('Unrecognized filter format; expecting FilterGroup');
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
  filterGroup: FilterGroup | undefined,
  resolutionMap: FilterResolutionMap,
) : Promise<boolean> => {
  // we are limited to certain filter keys right now, so better throw an explicit error if a key is not compatible
  // Note that similar check is done when saving a filter in stream, taxii, feed, or playbook node.
  // This check should thus not fail here, theoretically.
  if (filterGroup) validateFilterGroupForStixMatch(filterGroup);

  // first check: user access right to the element (according to markings, organization, etc.)
  const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stix);
  if (!isUserHasAccessToElement) {
    return false;
  }

  // if no filters and the user has access: the stix always match
  if (!filterGroup) return true;

  // replace the ids in values if necessary, to adapt to the stix format
  const resolvedFilterGroup = await resolveFilterGroup(context, user, filterGroup, resolutionMap);

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
export const isStixMatchFilterGroup = async (context: AuthContext, user: AuthUser, stix: any, filterGroup?: FilterGroup) : Promise<boolean> => {
  // resolve some of the ids as we filter on their corresponding values or standard-id for instance
  // the provided map will contain replacements for filter values, if any necessary.
  // we use the entities stored in cache for the "Resolved-Filters" (all the entities used by the saved filters - stream, trigger, playbooks)
  // see cacheManager.ts:platformResolvedFilters
  const cache = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  const map = filterGroup ? await buildResolutionMapForFilterGroup(context, user, filterGroup, cache) : new Map();

  return isStixMatchFilterGroup_MockableForUnitTests(context, user, stix, filterGroup, map);
};
