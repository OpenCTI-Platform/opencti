import { uniq } from 'ramda';
import { buildRefRelationKey } from '../../schema/general';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { availableStixCoreRelationships } from '../../database/stix';
import type { Filter, FilterGroup } from '../../generated/graphql';
import { FilterOperator } from '../../generated/graphql';
import { INSTANCE_FILTER, SIGHTED_BY_FILTER, specialFilterKeys } from './filtering-constants';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';

//----------------------------------------------------------------------------------------------------------------------
// Basic utility functions

/**
 * Tells if a filter group contains at least 1 filter or nested filter group
 * Note that it's a shallow check; it does not recurse into the nested groups.
 * @param filterGroup
 */
export const isFilterGroupNotEmpty = (filterGroup: FilterGroup) => {
  return filterGroup
    && (
      (filterGroup.filters && filterGroup.filters.length > 0)
      || (filterGroup.filterGroups && filterGroup.filterGroups.length > 0)
    );
};

/**
 * return the filter corresponding to the specified key (and operator if it is specified)
 * among a list of filters
 */
export const findFilterFromKey = (filtersList: Filter[], key: string, operator: FilterOperator | null = null) => {
  for (let index = 0; index < filtersList.length; index += 1) {
    const filter = filtersList[index];
    if (filter.key.includes(key)) {
      if (operator && filter.operator === operator) {
        return filter;
      }
      if (!operator) {
        return filter;
      }
    }
  }
  return null;
};

/**
 * Recursively build an array containing all the keys inside a FilterGroup and its nested groups, and returns it.
 * @param filterGroup
 */
export const extractFilterKeys = (filterGroup: FilterGroup): string[] => {
  let keys = filterGroup.filters.map((f) => f.key).flat() ?? [];
  if (filterGroup.filterGroups && filterGroup.filterGroups.length > 0) {
    keys = keys.concat(filterGroup.filterGroups.map((group) => extractFilterKeys(group)).flat());
  }
  return keys;
};

/**
 * extract all the values (ids) from a filter group
 * if key is specified: extract all the values corresponding to the specified keys
 * if key is specified and reverse=true: extract all the ids NOT corresponding to any key
 */
export const extractFilterGroupValues = (inputFilters: FilterGroup, key: string | string[] | null = null, reverse = false): string[] => {
  const keysToKeep = Array.isArray(key) ? key : [key];
  const { filters = [], filterGroups = [] } = inputFilters;
  let filteredFilters = [];
  if (key) {
    filteredFilters = reverse
      // we prefer to handle single key and multi keys here, but theoretically it should be arrays every time
      ? filters.filter((f) => (Array.isArray(f.key) ? f.key.every((k) => !keysToKeep.includes(k)) : f.key !== key))
      : filters.filter((f) => (Array.isArray(f.key) ? f.key.some((k) => keysToKeep.includes(k)) : f.key === key));
  } else {
    filteredFilters = filters;
  }
  let ids = filteredFilters.map((f) => f.values).flat() ?? [];
  if (filterGroups.length > 0) {
    ids = ids.concat(filterGroups.map((group) => extractFilterGroupValues(group, key)).flat());
  }
  return uniq(ids);
};

/**
 * Insert a Filter inside a FilterGroup
 * If the input filterGroup is not defined, it will return a new filterGroup with only the added filter (and / or).
 * Note that this function does input coercion, accepting string[] and string alike
 */
export const addFilter = (filterGroup: FilterGroup | undefined | null, newKey: string | string[], newValues: string | string[] | undefined | null, operator = 'eq'): FilterGroup => {
  const keyArray = Array.isArray(newKey) ? newKey : [newKey];
  let valuesArray: string[] = [];
  if (newValues) {
    valuesArray = Array.isArray(newValues) ? newValues : [newValues];
  }
  return {
    mode: filterGroup?.mode ?? 'and',
    filters: [
      {
        key: keyArray,
        values: valuesArray,
        operator,
        mode: 'or'
      },
      ...(filterGroup?.filters ?? [])
    ],
    filterGroups: filterGroup?.filterGroups ?? [],
  } as FilterGroup;
};

const replaceFilterKeyInFilter = (filter: Filter, oldKey: string, newKey: string) : Filter => {
  return {
    ...filter,
    key: filter.key.map((k) => (k === oldKey ? newKey : oldKey)),
  };
};

export const replaceFilterKey = (filterGroup: FilterGroup, oldKey: string, newKey: string) : FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => replaceFilterKeyInFilter(f, oldKey, newKey)),
    filterGroups: filterGroup.filterGroups.map(((fg) => replaceFilterKey(fg, oldKey, newKey)))
  };
};

//----------------------------------------------------------------------------------------------------------------------
// Filter adaptation

// map of the special filtering keys that should be converted
// the first element of the map is the frontend key
// the second element is the converted key used in backend
const specialFilterKeysConvertor = new Map([
  [SIGHTED_BY_FILTER, buildRefRelationKey(STIX_SIGHTING_RELATIONSHIP)],
  [INSTANCE_FILTER, buildRefRelationKey('*')],
]);

/**
 * Return a filterGroup where all special keys (rel refs) have been converted from frontend format to backend format
 * @param filterGroup
 */
const convertRelationRefsFilterKeys = (filterGroup: FilterGroup): FilterGroup => {
  if (filterGroup && isFilterGroupNotEmpty(filterGroup)) {
    const { filters = [], filterGroups = [] } = filterGroup;
    const newFiltersContent: Filter[] = [];
    const newFilterGroups: FilterGroup[] = [];
    if (filterGroups.length > 0) {
      for (let i = 0; i < filterGroups.length; i += 1) {
        const group = filterGroups[i];
        const convertedGroup = convertRelationRefsFilterKeys(group);
        newFilterGroups.push(convertedGroup);
      }
    }
    filters.forEach((f) => {
      const filterKeys = Array.isArray(f.key) ? f.key : [f.key];
      const convertedFilterKeys = filterKeys
        .map((key) => specialFilterKeysConvertor.get(key) ?? key) // 1. convert special keys
        .map((key) => [key, schemaRelationsRefDefinition.getDatabaseName(key) ?? '']) // 2. fetch eventual ref database names
        .map(([key, databaseName]) => (databaseName ? buildRefRelationKey(databaseName) : key)); // 3. convert databaseName if exists or keep initial key if not
      newFiltersContent.push({ ...f, key: convertedFilterKeys });
    });
    return {
      mode: filterGroup.mode,
      filters: newFiltersContent,
      filterGroups: newFilterGroups,
    };
  }
  // empty or undefined -> untouched
  return filterGroup;
};

/**
 * Go through all keys in a filter group to:
 * - check that the key is available with respect to the schema, throws an Error if not
 * - convert relation refs key if any
 * @param filterGroup
 */
export const checkAndConvertFilters = (filterGroup?: FilterGroup) => {
  // TODO improvement: check filters keys correspond to the entity types if types is given
  if (filterGroup && isFilterGroupNotEmpty(filterGroup)) {
    // 01. check filters keys exist in schema
    const keys = extractFilterKeys(filterGroup)
      .map((k) => k.split('.')[0]); // keep only the first part of the key to handle composed keys
    if (keys.length > 0) {
      let incorrectKeys = keys;
      const availableAttributes = schemaAttributesDefinition.getAllAttributesNames();
      const availableRelations = schemaRelationsRefDefinition.getAllInputNames();
      const availableStixCoreRelations = availableStixCoreRelationships();
      const extendedAvailableStixCoreRelations = availableStixCoreRelations.concat(availableStixCoreRelations.map((relationName) => `rel_${relationName}`)); // for relations entity ids contained in an entity
      const availableKeys = availableAttributes
        .concat(availableRelations)
        .concat(extendedAvailableStixCoreRelations)
        .concat(specialFilterKeys);
      keys.forEach((k) => {
        if (availableKeys.includes(k)) {
          incorrectKeys = incorrectKeys.filter((n) => n !== k);
        }
      });
      if (incorrectKeys.length > 0) {
        throw Error(`incorrect filter keys: ${incorrectKeys} not existing in any schema definition`);
      }
    }

    // 02. translate the filter keys on relation refs and return the converted filters
    return convertRelationRefsFilterKeys(filterGroup);
  }

  // nothing to convert
  return filterGroup;
};
