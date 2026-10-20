import { type FilterEventContext, type ReadonlyStix, type TesterFunction, testFilterGroup } from '../boolean-logic-engine';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../../access';
import type { AuthContext, AuthUser } from '../../../types/user';
import { getEntitiesMapFromCache } from '../../../database/cache';
import type { StixObject } from '../../../types/stix-2-1-common';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../../schema/stixDomainObject';
import { type FilterGroup } from '../../../generated/graphql';
import type { FilterResolutionMap } from '../filtering-resolution';
import { buildResolutionMapForFilterGroup, resolveFilterGroup } from '../filtering-resolution';
import { UnsupportedError } from '../../../config/errors';
import { checkFiltersFormat, extractFilterKeys } from '../filtering-utils';
import { getFullFilterKeyTestersMap } from './stix-testers';
import { isCustomFieldFilterKey } from '../filtering-constants';
import { deletedCustomFieldStixFilterTester } from '../../../modules/customField/custom-field-stix-utils';

// ----------------------------------------------------------------------------------------------------------------------

/**
 * check a FilterGroup's keys validity in stix filtering
 */
const checkFiltersKeysForStixMatch = (
  filterGroup: FilterGroup,
  filtersKeyTestersMap: Record<string, TesterFunction>,
  isUnknownCustomFieldAccepted: boolean,
) => {
  filterGroup.filters.forEach((filter) => {
    if (!Array.isArray(filter.key)) {
      throw UnsupportedError('The provided filter key is not an array', { key: JSON.stringify(filter.key) });
    }
    if (filter.key.length !== 1) {
      throw UnsupportedError('Stix filtering can only be executed on a unique filter key', { key: JSON.stringify(filter.key) });
    }
    // When matching, a stored filter on a since deleted custom field stays valid, see getFilterKeyTestersMapForFilterGroup
    const isCustomFieldKey = isCustomFieldFilterKey(filter.key[0]);
    if (filtersKeyTestersMap[filter.key[0]] === undefined && !(isUnknownCustomFieldAccepted && isCustomFieldKey)) {
      const availableFilters = JSON.stringify(Object.keys(filtersKeyTestersMap));
      // The message names the custom field, typically deleted since, so that its filter can be found and removed
      const message = isCustomFieldKey
        ? `The filter key ${filter.key[0]} does not match any existing custom field`
        : 'Stix filtering is not compatible with the provided filter key';
      throw UnsupportedError(message, { key: JSON.stringify(filter.key), availableFilters });
    }
  });
  filterGroup.filterGroups.forEach((fg) => checkFiltersKeysForStixMatch(fg, filtersKeyTestersMap, isUnknownCustomFieldAccepted));
};

const checkFilterGroupForStixMatch = async (context: AuthContext, user: AuthUser, filterGroup: FilterGroup, isUnknownCustomFieldAccepted: boolean) => {
  // check filters format
  checkFiltersFormat(filterGroup);
  // check filters keys validity
  const fullFiltersKeyTestersMap = await getFullFilterKeyTestersMap(context, user);
  checkFiltersKeysForStixMatch(filterGroup, fullFiltersKeyTestersMap, isUnknownCustomFieldAccepted);
};

/**
 * validate a FilterGroup in stix filtering before saving it: check the filters format and the filter keys validity
 * (a custom field key must match an existing custom field definition, as any other key)
 */
export const validateFilterGroupForStixMatch = async (context: AuthContext, user: AuthUser, filterGroup: FilterGroup) => {
  await checkFilterGroupForStixMatch(context, user, filterGroup, false);
};

// ----------------------------------------------------------------------------------------------------------------------
// STIX MATCH

// The testers of the filter group keys, with a filter on a deleted custom field tested as a custom field no stix has
const getFilterKeyTestersMapForFilterGroup = async (context: AuthContext, user: AuthUser, filterGroup: FilterGroup) => {
  const testersMap = await getFullFilterKeyTestersMap(context, user);
  extractFilterKeys(filterGroup)
    .filter((key) => isCustomFieldFilterKey(key) && testersMap[key] === undefined)
    .forEach((key) => {
      testersMap[key] = deletedCustomFieldStixFilterTester;
    });
  return testersMap;
};

/**
 * Middleware function that allow us to make unit tests by mocking the resolution map.
 * This is necessary because the map is built thanks to the cache, not available in unit tests.
 */
export const isStixMatchFilterGroup_MockableForUnitTests = async (
  context: AuthContext,
  user: AuthUser,
  stix: ReadonlyStix,
  filterGroup: FilterGroup | undefined,
  resolutionMap: FilterResolutionMap,
  eventContext?: FilterEventContext,
): Promise<boolean> => {
  // we are limited to certain filter keys right now, so better throw an explicit error if a key is not compatible
  // Note that similar check is done when saving a filter in stream, taxii, feed, or playbook node.
  // This check should thus not fail here, theoretically.
  if (filterGroup) {
    await checkFilterGroupForStixMatch(context, user, filterGroup, true);
  }

  // first check: user access right to the element (according to markings, organization, etc.)
  const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stix as StixObject);
  if (!isUserHasAccessToElement) {
    return false;
  }

  // if no filters and the user has access: the stix always match
  if (!filterGroup) return true;

  // replace the ids in values if necessary, to adapt to the stix format
  const resolvedFilterGroup = await resolveFilterGroup(context, user, filterGroup, resolutionMap);

  // then call our boolean engine on the filter group using the stix testers
  const fullFiltersKeyTestersMap = await getFilterKeyTestersMapForFilterGroup(context, user, resolvedFilterGroup);
  return testFilterGroup(stix, resolvedFilterGroup, fullFiltersKeyTestersMap, eventContext);
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
 * @param eventContext optional event context for has_changed/not_has_changed operator evaluation
 * @throws {Error} on invalid filter keys
 */
export const isStixMatchFilterGroup = async (
  context: AuthContext,
  user: AuthUser,
  stix: any,
  filterGroup?: FilterGroup,
  eventContext?: FilterEventContext,
): Promise<boolean> => {
  // resolve some of the ids as we filter on their corresponding values or standard-id for instance
  // the provided map will contain replacements for filter values, if any necessary.
  // we use the entities stored in cache for the "Resolved-Filters" (all the entities used by the saved filters - stream, trigger, playbooks)
  // see cacheManager.ts:platformResolvedFilters
  const cache = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  const map = filterGroup ? await buildResolutionMapForFilterGroup(context, user, filterGroup, cache) : new Map();

  return isStixMatchFilterGroup_MockableForUnitTests(context, user, stix, filterGroup, map, eventContext);
};
