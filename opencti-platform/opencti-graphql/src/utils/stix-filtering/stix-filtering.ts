import { INDICATOR_FILTER, } from '../filtering';
import { FILTER_KEY_TESTERS_MAP } from './stix-testers';
import { testFilterGroup } from './boolean-logic-engine';
import type { Filter, FilterGroup } from './filter-group';
import { getEntitiesMapFromCache } from '../../database/cache';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../access';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../schema/stixDomainObject';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StixId, StixObject } from '../../types/stix-common';
import { extractStixRepresentative } from '../../database/stix-representative';

// TODO: changed by Cathia for #2686, to integrate properly next
const LABEL_FILTER = 'objectLabel';

//----------------------------------------------------------------------------------------------------------

type ResolutionMap = Map<string | StixId, StixObject>;

/**
 * Resolve some of the values (recursively) inside the filter group
 * so that testers work properly on either the unresolved ids or the resolved values (from the ids)
 * To date, we need to use the resolved values instead of ids for: Indicators, labels.
 */
export const resolveFilter = (filter: Filter, resolutionMap: ResolutionMap): Filter => {
  // resolve labels and indicators values using the resolutionMap
  if (filter.key[0] === INDICATOR_FILTER || filter.key[0] === LABEL_FILTER) {
    const newFilterValues: string [] = [];
    filter.values.forEach((id) => {
      const resolution = resolutionMap.get(id);
      if (resolution) {
        const value = extractStixRepresentative(resolution);
        newFilterValues.push(value);
      }
    });

    return {
      ...filter,
      values: newFilterValues
    };
  }
  // filter is untouched otherwise
  return filter;
};

/**
 * Recursively resolve some ids in the filter, see resolveFilter
 * @param filterGroup
 * @param resolutionMap the map <id, StixObject> holding the whole object resolution
 */
export const resolveFilterGroup = (filterGroup: FilterGroup, resolutionMap: ResolutionMap): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => resolveFilter(f, resolutionMap)),
    filterGroups: filterGroup.filterGroups.map((fg) => resolveFilterGroup(fg, resolutionMap))
  };
};

/**
 * Pass through all individual filters and throws an error if it cannot be handled properly.
 * This is very aggressive but will allow us to detect rapidly any corner-case.
 */
export const validateFilter = (filter: Filter) => {
  if (filter.key.length !== 1) {
    throw new Error(`Stix filtering can only be executed on a unique filter key - got ${JSON.stringify(filter.key)}`);
  }
  if (FILTER_KEY_TESTERS_MAP[filter.key[0]] === undefined) {
    throw new Error(`Stix filtering is not compatible with the provided filter key ${JSON.stringify(filter.key)}`);
  }
};

/**
 * Recursively call validateFilter inside a FilterGroup
 */
export const validateFilterGroup = (filterGroup: FilterGroup) => {
  filterGroup.filters.forEach((f) => validateFilter(f));
  filterGroup.filterGroups.forEach((fg) => validateFilterGroup(fg));
};

/**
 * Tells if a stix object matches a given FilterGroup.
 * This function returns false when user does not have sufficient access rights on the object.
 * @throws {Error} when filter group is invalid (keys not handled).
 */
export const isStixMatchFilterGroup = async (context: AuthContext, user: AuthUser, stix: any, filterGroup: FilterGroup) : Promise<boolean> => {
  // throws on unhandled filter groups
  validateFilterGroup(filterGroup);

  // first check: user access right (according to markings, organization, etc.)
  const isUserHasAccessToElement = await isUserCanAccessStixElement(context, user, stix);
  if (!isUserHasAccessToElement) {
    return false;
  }

  // TODO add the preprocessing done by Cathia for #2686
  // that enhance the ids with standard ids, check access rights of some ids etc.

  // get the resolution map once and for all, not in the recursion
  const resolutionMap: ResolutionMap = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);

  //  resolve some of the ids as we filter on their corresponding values
  const resolvedFilterGroup = resolveFilterGroup(filterGroup, resolutionMap);

  // then call our boolean engine on the filter group using the stix testers
  return testFilterGroup(stix, resolvedFilterGroup, FILTER_KEY_TESTERS_MAP);
};
