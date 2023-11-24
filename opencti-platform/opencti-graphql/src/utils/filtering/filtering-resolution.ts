import type { Filter, FilterGroup } from '../../generated/graphql';
import { FilterMode, FilterOperator } from '../../generated/graphql';
import {
  ASSIGNEE_FILTER,
  CONNECTED_TO_INSTANCE_FILTER,
  CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER,
  CREATED_BY_FILTER,
  INDICATOR_FILTER,
  INSTANCE_FILTER,
  LABEL_FILTER,
  MARKING_FILTER,
  OBJECT_CONTAINS_FILTER,
  PARTICIPANT_FILTER,
  RELATION_FROM_FILTER,
  RELATION_TO_FILTER,
} from './filtering-constants';
import type { AuthContext, AuthUser } from '../../types/user';
import type { StixObject } from '../../types/stix-common';
import { isUserCanAccessStixElement, SYSTEM_USER } from '../access';
import { getEntitiesMapFromCache } from '../../database/cache';
import { ENTITY_TYPE_RESOLVED_FILTERS } from '../../schema/stixDomainObject';
import { checkAndConvertFilters, extractFilterGroupValues } from './filtering-utils';

// list of all filters that needs resolution
export const RESOLUTION_FILTERS = [
  LABEL_FILTER,
  MARKING_FILTER,
  CREATED_BY_FILTER,
  ASSIGNEE_FILTER,
  PARTICIPANT_FILTER,
  OBJECT_CONTAINS_FILTER,
  RELATION_FROM_FILTER,
  RELATION_TO_FILTER,
  INSTANCE_FILTER,
  CONNECTED_TO_INSTANCE_FILTER,
  CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER,
];

export type FilterResolutionMap = Map<string, string>;

// map (filter key) <-> (corresponding prop key in a stix object)
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
  [CONNECTED_TO_INSTANCE_FILTER]: 'id', // instance trigger --> resolve with the standard id (which is the stix.id)
  [CONNECTED_TO_INSTANCE_SIDE_EVENTS_FILTER]: 'id', // instance trigger --> resolve with the standard id (which is the stix.id)
};

//----------------------------------------------------------------------------------------------------------------------

/**
 * Resolve some of the filter values according to a resolution map.
 * This concerns attributes that are not directly compared with a stix attribute due to modelization differences.
 * For instance, labels are entities internally, and filter.values would contain these entities internal ids.
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

/**
 * Build a resolution map thanks to the cache
 */
const buildResolutionMapForFilter = async (context: AuthContext, user: AuthUser, filter: Filter, cache: Map<string, StixObject>) : Promise<FilterResolutionMap> => {
  const map: Map<string, string> = new Map();
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
          map.set(v, '<restricted-or-deleted>');
        } else {
          // resolve according to path
          const cachedValue = cachedObject[path];
          if (typeof cachedValue === 'string') {
            map.set(v, cachedValue);
          }
        }
      }
    }
  }

  return map;
};

/**
 * recursively call buildResolutionMapForFilter inside a filter group
 */
export const buildResolutionMapForFilterGroup = async (
  context: AuthContext,
  user: AuthUser,
  filterGroup: FilterGroup,
  cache: Map<string, StixObject>
): Promise<FilterResolutionMap> => {
  const filtersMaps = await Promise.all(filterGroup.filters.map((f) => buildResolutionMapForFilter(context, user, f, cache)));
  const filterGroupsMaps = await Promise.all(filterGroup.filterGroups.map((fg) => buildResolutionMapForFilterGroup(context, user, fg, cache)));
  // merge all maps into one; for a given unique key the last value wins
  return new Map([...new Map(...filtersMaps), ...new Map(...filterGroupsMaps)]);
};

/**
 * Resolve some values into what's comparable in stix format using the cache
 * TODO: Not unit-testable for now because of the cache that exists only at runtime (getEntitiesMapFromCache)
 */
export const resolveFilterGroupValuesWithCache = async (context: AuthContext, user: AuthUser, filterGroup: FilterGroup) => {
  const cache = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  const resolutionMap = await buildResolutionMapForFilterGroup(context, user, filterGroup, cache);

  return resolveFilterGroup(filterGroup, resolutionMap);
};

//----------------------------------------------------------------------------------------------------------------------

/**
 * Extract all filter values (ids) that might require a resolution from cache "Resolved-Filters"
 * @param filterGroup
 */
export const extractFilterGroupValuesToResolveForCache = (filterGroup: FilterGroup) => {
  return extractFilterGroupValues(filterGroup, RESOLUTION_FILTERS);
};

// build a map ([id]: StixObject) with the resolved filters accessible for a user
// used for instance trigger side events message display only !!!
export const resolveFiltersMapForUser = async (context: AuthContext, user: AuthUser, inputFilters?: FilterGroup) => {
  const resolveUserMap = new Map();
  if (!inputFilters) return resolveUserMap;
  const resolvedMap = await getEntitiesMapFromCache<StixObject>(context, SYSTEM_USER, ENTITY_TYPE_RESOLVED_FILTERS);
  const { filters } = inputFilters; // instance triggers don't handle imbricated filterGroups, we only handle filters at the first level
  for (let index = 0; index < filters.length; index += 1) {
    const { values = [] } = filters[index];
    for (let vIndex = 0; vIndex < values.length; vIndex += 1) {
      const v = values[vIndex];
      if (resolvedMap.has(v)) {
        const stixInstance = resolvedMap.get(v);
        const isUserHasAccessToElement = !!stixInstance && await isUserCanAccessStixElement(context, user, stixInstance);
        if (isUserHasAccessToElement) {
          resolveUserMap.set(stixInstance.id, stixInstance);
        }
      }
    }
  }
  return resolveUserMap;
};

export const convertFiltersToQueryOptions = async (context: AuthContext, user: AuthUser, filters: FilterGroup | null, opts: any = {}) => {
  const { after, before, defaultTypes = [], field = 'updated_at', orderMode = 'asc' } = opts;
  const types = [...defaultTypes];
  const convertedFilters = filters ? checkAndConvertFilters(filters) : undefined;
  const finalFilters = convertedFilters
    ? await resolveFilterGroupValuesWithCache(context, user, convertedFilters)
    : {
      mode: FilterMode.And,
      filters: [],
      filterGroups: [],
    };
  if (after) {
    finalFilters.filters.push({ key: field, values: [after], operator: FilterOperator.Gte });
  }
  if (before) {
    finalFilters.filters.push({ key: field, values: [before], operator: FilterOperator.Lte });
  }
  return { types, orderMode, orderBy: [field, 'internal_id'], filters: finalFilters };
};
