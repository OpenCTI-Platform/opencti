import { uniq } from 'ramda';
import { buildRefRelationKey, RULE_PREFIX } from '../../schema/general';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import type { Filter, FilterGroup } from '../../generated/graphql';
import { FilterOperator } from '../../generated/graphql';
import {
  CONTEXT_CREATED_BY_FILTER,
  CONTEXT_CREATOR_FILTER,
  CONTEXT_ENTITY_ID_FILTER,
  CONTEXT_ENTITY_TYPE_FILTER,
  CONTEXT_OBJECT_LABEL_FILTER,
  CONTEXT_OBJECT_MARKING_FILTER,
  INSTANCE_FILTER,
  internalFilterKeys,
  MEMBERS_GROUP_FILTER,
  MEMBERS_ORGANIZATION_FILTER,
  MEMBERS_USER_FILTER,
  nestedFilterKeys,
  SIGHTED_BY_FILTER,
  specialFilterKeys
} from './filtering-constants';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { UnsupportedError } from '../../config/errors';

//----------------------------------------------------------------------------------------------------------------------
// Basic utility functions

/**
 * Tells if a filter group is in the correct format
 * (Enables to check filters are not in the old format)
 * Note that it's a shallow check; it does not recurse into the nested groups.
 * @param filterGroup
 */
export const isFilterGroupFormatCorrect = (filterGroup: FilterGroup) => {
  return (filterGroup.mode
    && filterGroup.filters && Array.isArray(filterGroup.filters)
    && filterGroup.filterGroups && Array.isArray(filterGroup.filters));
};

/**
 * Tells if a filter group contains at least 1 filter or nested filter group
 * Note that it's a shallow check; it does not recurse into the nested groups.
 * @param filterGroup
 */
export const isFilterGroupNotEmpty = (filterGroup?: FilterGroup) => {
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
export const findFiltersFromKey = (filtersList: Filter[], key: string, operator: FilterOperator | null = null) => {
  const foundFilters = [];
  for (let index = 0; index < filtersList.length; index += 1) {
    const filter = filtersList[index];
    if (filter.key.includes(key)) {
      if (operator && filter.operator === operator) {
        foundFilters.push(filter);
      }
      if (!operator) {
        foundFilters.push(filter);
      }
    }
  }
  return foundFilters;
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
    ids = ids.concat(filterGroups.map((group) => extractFilterGroupValues(group, key, reverse)).flat());
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

/**
 * Parse recursively a filterg group and replace all occurrences of a filter key with a new key
 * @param filterGroup
 * @param oldKey
 * @param newKey
 */
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
  [CONTEXT_ENTITY_ID_FILTER, 'context_data.id'],
  [CONTEXT_ENTITY_TYPE_FILTER, 'context_data.entity_type'],
  [CONTEXT_CREATOR_FILTER, 'context_data.creator_id'],
  [CONTEXT_CREATED_BY_FILTER, 'context_data.created_by_ref_id'],
  [CONTEXT_OBJECT_MARKING_FILTER, 'context_data.object_marking_refs_ids'],
  [CONTEXT_OBJECT_LABEL_FILTER, 'context_data.labels_ids'],
  [MEMBERS_USER_FILTER, 'user_id'],
  [MEMBERS_GROUP_FILTER, 'group_ids'],
  [MEMBERS_ORGANIZATION_FILTER, 'organization_ids'],
]);

/**
 * Return a filterGroup where all special keys (rel refs) have been converted from frontend format to backend format
 * @param filterGroup
 */
const convertRelationRefsFilterKeys = (filterGroup: FilterGroup): FilterGroup => {
  if (isFilterGroupNotEmpty(filterGroup)) {
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
        .map((key) => specialFilterKeysConvertor.get(key) ?? key) //  convert special keys
        .map((key) => (STIX_CORE_RELATIONSHIPS.includes(key) ? buildRefRelationKey(key) : key)) // convert relation keys -> rel_X or keep key
        .map((key) => [key, schemaRelationsRefDefinition.getDatabaseName(key) ?? '']) // fetch eventual ref database names
        .map(([key, name]) => (name ? buildRefRelationKey(name) : key)); // convert databaseName if exists or keep initial key if not
      newFiltersContent.push({ ...f, key: convertedFilterKeys });
    });
    return {
      mode: filterGroup.mode,
      filters: newFiltersContent,
      filterGroups: newFilterGroups,
    };
  }
  // empty -> untouched
  return filterGroup;
};

// input: an array of relations names
// return an array of the converted names in the rel_'database_name' format
const getConvertedRelationsNames = (relationNames: string[]) => {
  const convertedRelationsNames = relationNames.map((relationName) => `rel_${relationName}`);
  convertedRelationsNames.push('rel_*'); // means 'all the relations'
  return convertedRelationsNames;
};

/**
 * Go through all keys in a filter group to:
 * - check that the key is available with respect to the schema, throws an Error if not
 * - convert relation refs key if any
 */
export const checkAndConvertFilters = (filterGroup: FilterGroup | null | undefined, opts: { noFiltersChecking?: boolean, authorizeNestedFiltersKeys?: boolean } = {}) => {
  if (!filterGroup) {
    return undefined;
  }
  if (!isFilterGroupFormatCorrect(filterGroup)) { // detect filters in the old format or in a bad format
    throw UnsupportedError('Incorrect filters format', { filter: JSON.stringify(filterGroup) });
  }
  const { noFiltersChecking = false, authorizeNestedFiltersKeys = false } = opts;
  // 01. check filters keys exist in schema
  // TODO improvement: check filters keys correspond to the entity types if types is given
  if (!noFiltersChecking && isFilterGroupNotEmpty(filterGroup)) {
    const keys = extractFilterKeys(filterGroup)
      .map((k) => k.split('.')[0]); // keep only the first part of the key to handle composed keys
    if (keys.length > 0) {
      let incorrectKeys = keys;
      const availableAttributes = schemaAttributesDefinition.getAllAttributesNames();
      const availableRefRelations = schemaRelationsRefDefinition.getAllInputNames();
      const availableConvertedRefRelations = getConvertedRelationsNames(schemaRelationsRefDefinition.getAllDatabaseName());
      const availableConvertedStixCoreRelationships = getConvertedRelationsNames(STIX_CORE_RELATIONSHIPS);
      let availableKeys = availableAttributes
        .concat(availableRefRelations)
        .concat(availableConvertedRefRelations)
        .concat(STIX_CORE_RELATIONSHIPS)
        .concat(availableConvertedStixCoreRelationships)
        .concat(specialFilterKeys)
        .concat(internalFilterKeys);
      if (authorizeNestedFiltersKeys) {
        availableKeys = availableKeys.concat(nestedFilterKeys);
      }
      keys.forEach((k) => {
        if (availableKeys.includes(k) || k.startsWith(RULE_PREFIX)) {
          incorrectKeys = incorrectKeys.filter((n) => n !== k);
        }
      });
      if (incorrectKeys.length > 0) {
        throw UnsupportedError('incorrect filter keys not existing in any schema definition', { keys: incorrectKeys });
      }
    }

    // 02. translate the filter keys on relation refs and return the converted filters
    return convertRelationRefsFilterKeys(filterGroup);
  }

  // nothing to convert
  return filterGroup;
};
