import { uniq } from 'ramda';
import { buildRefRelationKey, REL_INDEX_PREFIX, RULE_PREFIX } from '../../schema/general';
import { schemaAttributesDefinition } from '../../schema/schema-attributes';
import { schemaRelationsRefDefinition } from '../../schema/schema-relationsRef';
import { type Filter, type FilterGroup, FilterMode, FilterOperator } from '../../generated/graphql';
import {
  CONTEXT_CREATED_BY_FILTER,
  CONTEXT_CREATOR_FILTER,
  CONTEXT_ENTITY_ID_FILTER,
  CONTEXT_ENTITY_TYPE_FILTER,
  CONTEXT_OBJECT_LABEL_FILTER,
  CONTEXT_OBJECT_MARKING_FILTER,
  FILTER_KEYS_WITH_ME_VALUE,
  INSTANCE_DYNAMIC_REGARDING_OF,
  INSTANCE_REGARDING_OF,
  LABEL_FILTER,
  ME_FILTER_VALUE,
  MEMBERS_GROUP_FILTER,
  MEMBERS_ORGANIZATION_FILTER,
  MEMBERS_USER_FILTER,
  OPINIONS_METRICS_MAX_FILTER,
  OPINIONS_METRICS_MEAN_FILTER,
  OPINIONS_METRICS_MIN_FILTER,
  OPINIONS_METRICS_TOTAL_FILTER,
  RELATION_DYNAMIC_FROM_FILTER,
  RELATION_DYNAMIC_TO_FILTER,
  SIGHTED_BY_FILTER,
  SPECIAL_FILTER_KEYS,
} from './filtering-constants';
import { STIX_SIGHTING_RELATIONSHIP } from '../../schema/stixSightingRelationship';
import { STIX_CORE_RELATIONSHIPS } from '../../schema/stixCoreRelationship';
import { UnsupportedError } from '../../config/errors';
import { isNotEmptyField } from '../../database/utils';
import { isInternalId, isValidDate } from '../../schema/schemaUtils';
import type { AuthContext, AuthUser } from '../../types/user';
import type { BasicStoreObject } from '../../types/store';
import { idLabel } from '../../schema/schema-labels';
import { INTERNAL_RELATIONSHIPS } from '../../schema/internalRelationship';
import { getMetricsAttributesNames } from '../../modules/metrics/metrics-utils';

export const emptyFilterGroup: FilterGroup = {
  mode: FilterMode.And,
  filters: [],
  filterGroups: [],
};

// ----------------------------------------------------------------------------------------------------------------------
// Basic utility functions

export const isFilterFormatCorrect = (filter: Filter) => {
  // TODO complete (regardingOf checks, nested filters checks, within/nil operators checks, etc)
  return (
    filter.key && isNotEmptyField(filter.key)
  );
};

/**
 * Tells if a filter group is in the correct format
 * (Enables to check filters are not in the old format)
 * Note that it's a shallow check; it does not recurse into the nested groups.
 * @param filterGroup
 */
const isFilterGroupFormatCorrect = (filterGroup: FilterGroup): boolean => {
  return (filterGroup.mode
    && ['and', 'or'].includes(filterGroup.mode)
    && filterGroup.filters && Array.isArray(filterGroup.filters)
    && filterGroup.filters.every((f) => isFilterFormatCorrect(f))
    && filterGroup.filterGroups && Array.isArray(filterGroup.filterGroups)
    && filterGroup.filterGroups.every((fg) => isFilterGroupFormatCorrect(fg))
  );
};

/**
 * Tells if a filter group values are valid
 * (Enables to check filters won't raise an error at the query resolution)
 * Only implemented for the 'within' operator for the moment
 * @param filterGroup
 */
export const checkFilterGroupValuesSyntax = (filterGroup: FilterGroup) => {
  // 'within' operator
  const withinFilters = filterGroup.filters.filter((f) => f.operator === FilterOperator.Within);
  withinFilters.forEach((f) => {
    const { values } = f;
    if (values.length !== 2) {
      throw UnsupportedError('A filter with "within" operator must have 2 values', { filter: f });
    }
    if (values.some((v) => v === null || v === '')) {
      throw UnsupportedError('A filter with "within" operator must have 2 values', { filter: f });
    }
    const relative_date_regex = /^now([-+]\d+[smhHdwMy](\/[smhHdwMy])?)?$/;
    if (values.some((v) => !relative_date_regex.test(v) && !isValidDate(v))) {
      throw UnsupportedError('The values for filter with "within" operator are not valid: you should provide a datetime or a valid relative date.', { filter: f });
    }
  });
  // recursively check the syntax of sub filter groups
  filterGroup.filterGroups.forEach((fg) => checkFilterGroupValuesSyntax(fg));
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
 * extract all the filters from a filter group for specified keys
 */
export const extractFiltersFromGroup = (inputFilters: FilterGroup, keysToKeep: string[]): Filter[] => {
  const { filters = [], filterGroups = [] } = inputFilters;
  const filteredFilters = filters.filter((f) => (Array.isArray(f.key) ? f.key.some((k) => keysToKeep.includes(k)) : keysToKeep.includes(f.key)));
  filteredFilters.push(...filterGroups.map((group) => extractFiltersFromGroup(group, keysToKeep)).flat());
  return filteredFilters;
};

/**
 * extract all the values (ids) from a filter group
 * if key is specified: extract all the values corresponding to the specified keys
 * if key is specified and reverse=true: extract all the ids NOT corresponding to any key
 * if lookInDynamicFilters = true: also extract values corresponding to the key in dynamic filters
 */
export const extractFilterGroupValues = (
  inputFilters: FilterGroup,
  key: string | string[] | null = null,
  reverse = false,
  lookInDynamicFilters = false,
): string[] => {
  const keysToKeep = Array.isArray(key) ? key : [key];
  if (lookInDynamicFilters) {
    keysToKeep.push(...[INSTANCE_DYNAMIC_REGARDING_OF, RELATION_DYNAMIC_TO_FILTER, RELATION_DYNAMIC_FROM_FILTER]);
  }
  const { filters = [], filterGroups = [] } = inputFilters;
  let filteredFilters = [];
  if (key) {
    filteredFilters = reverse
      // we prefer to handle single key and multi keys here, but theoretically it should be arrays every time
      ? filters.filter((f) => (Array.isArray(f.key) ? f.key.every((k) => !keysToKeep.includes(k)) : !keysToKeep.includes(f.key)))
      : filters.filter((f) => (Array.isArray(f.key) ? f.key.some((k) => keysToKeep.includes(k)) : keysToKeep.includes(f.key)));
  } else {
    filteredFilters = filters;
  }

  const ids = [];
  // we need to extract the ids that need representatives resolution
  filteredFilters.forEach((f) => {
    // regardingOf key is a composite filter id+type, values are [{ key: 'id', ...}, { key: 'relationship_type', ... }]
    if (f.key.includes(INSTANCE_REGARDING_OF)) {
      const regardingIds = f.values.find((v) => v.key === 'id')?.values ?? [];
      ids.push(...regardingIds);
    } else if (f.key.includes(INSTANCE_DYNAMIC_REGARDING_OF)) {
      // values of 'dynamic' subfilter are filters we should look for
      const dynamicValues = f.values.find((v) => v.key === 'dynamic')?.values ?? [];
      const dynamicIds = dynamicValues.map((v: FilterGroup) => extractFilterGroupValues(v, key, reverse)).flat();
      ids.push(...dynamicIds);
      ids.push('dynamic');
    } else if (f.key.includes(RELATION_DYNAMIC_FROM_FILTER) || f.key.includes(RELATION_DYNAMIC_TO_FILTER)) {
      // values are filters we should look for
      const dynamicIds = f.values.map((v) => extractFilterGroupValues(v, key, reverse)).flat();
      ids.push(...dynamicIds);
      ids.push('dynamic');
    } else {
      ids.push(...f.values);
    }
  });
  // recurse on filter groups
  if (filterGroups.length > 0) {
    ids.push(...filterGroups.map((group) => extractFilterGroupValues(group, key, reverse)).flat());
  }
  return uniq(ids);
};

/**
 * extract all the values (dynamic filters) from a filter group
 * if key is specified: extract all the values corresponding to the specified keys
 * if key is specified and reverse=true: extract all the ids NOT corresponding to any key
 */
export const extractDynamicFilterGroupValues = (inputFilters: FilterGroup, key: string | string[] | null = null, reverse = false): FilterGroup[] => {
  const keysToKeep = Array.isArray(key) ? key : [key];
  const { filters = [], filterGroups = [] } = inputFilters;
  let filteredFilters = [];
  if (key) {
    filteredFilters = reverse
    // we prefer to handle single key and multi keys here, but theoretically it should be arrays every time
      ? filters.filter((f) => (Array.isArray(f.key) ? f.key.every((k) => !keysToKeep.includes(k)) : !keysToKeep.includes(f.key)))
      : filters.filter((f) => (Array.isArray(f.key) ? f.key.some((k) => keysToKeep.includes(k)) : keysToKeep.includes(f.key)));
  } else {
    filteredFilters = filters;
  }
  const ids = [];
  // we need to extract the ids that need representatives resolution
  filteredFilters.forEach((f) => {
    if (f.key.includes(INSTANCE_DYNAMIC_REGARDING_OF) || f.key.includes(RELATION_DYNAMIC_FROM_FILTER) || f.key.includes(RELATION_DYNAMIC_TO_FILTER)) {
      ids.push(...f.values);
    }
  });
  // recurse on filter groups
  if (filterGroups.length > 0) {
    ids.push(...filterGroups.map((group) => extractDynamicFilterGroupValues(group, key, reverse)).flat());
  }
  return ids;
};

/**
 * clear selected key(s) from filters
 */
export const clearKeyFromFilterGroup = (inputFilters: FilterGroup, key: string | string[]): FilterGroup => {
  const keysToRemove = Array.isArray(key) ? key : [key];
  const { filters = [], filterGroups = [] } = inputFilters;
  const filteredFilters = filters.filter((f) => (Array.isArray(f.key) ? f.key.every((k) => !keysToRemove.includes(k)) : !keysToRemove.includes(f.key)));
  let filteredFilterGroups: FilterGroup[] = [];
  if (filterGroups.length > 0) {
    filteredFilterGroups = filterGroups.map((group) => clearKeyFromFilterGroup(group, key));
  }
  return { filters: filteredFilters, filterGroups: filteredFilterGroups, mode: inputFilters.mode };
};

/**
 * Construct a filter: filterGroup AND (new filter constructed from key, values, operator and mode)
 * If the input filterGroup is not defined, it will return a new filterGroup with only the added filter (and / or).
 * Note that this function does input coercion, accepting string[] and string alike
 */
export const addFilter = (filterGroup: FilterGroup | undefined | null, newKey: string | string[], newValues: string | string[] | undefined | null, operator = 'eq', localMode = 'or'): FilterGroup => {
  const keyArray = Array.isArray(newKey) ? newKey : [newKey];
  let valuesArray: string[] = [];
  if (newValues) {
    valuesArray = Array.isArray(newValues) ? newValues : [newValues];
  }
  return {
    mode: 'and',
    filters: [
      {
        key: keyArray,
        values: valuesArray,
        operator,
        mode: localMode,
      },
    ],
    filterGroups: filterGroup && isFilterGroupNotEmpty(filterGroup) ? [filterGroup] : [],
  } as FilterGroup;
};

const replaceFilterKeyInFilter = (filter: Filter, oldKey: string, newKey: string): Filter => {
  return {
    ...filter,
    key: filter.key.map((k) => (k === oldKey ? newKey : k)),
  };
};

/**
 * Parse recursively a filterg group and replace all occurrences of a filter key with a new key
 * @param filterGroup
 * @param oldKey
 * @param newKey
 */
export const replaceFilterKey = (filterGroup: FilterGroup, oldKey: string, newKey: string): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => replaceFilterKeyInFilter(f, oldKey, newKey)),
    filterGroups: filterGroup.filterGroups.map((fg) => replaceFilterKey(fg, oldKey, newKey)),
  };
};

// ----------------------------------------------------------------------------------------------------------------------
// Filter adaptation

// map of the special filtering keys that should be converted
// the first element of the map is the frontend key
// the second element is the converted key used in backend
const specialFilterKeysConvertor = new Map([
  [SIGHTED_BY_FILTER, buildRefRelationKey(STIX_SIGHTING_RELATIONSHIP)],
  [OPINIONS_METRICS_MEAN_FILTER, 'opinions_metrics.mean'],
  [OPINIONS_METRICS_MAX_FILTER, 'opinions_metrics.max'],
  [OPINIONS_METRICS_MIN_FILTER, 'opinions_metrics.min'],
  [OPINIONS_METRICS_TOTAL_FILTER, 'opinions_metrics.total'],
  [CONTEXT_ENTITY_ID_FILTER, 'context_data.id'],
  [CONTEXT_ENTITY_TYPE_FILTER, 'context_data.entity_type'],
  [CONTEXT_CREATOR_FILTER, 'context_data.creator_ids'],
  [CONTEXT_CREATED_BY_FILTER, 'context_data.created_by_ref_id'],
  [CONTEXT_OBJECT_MARKING_FILTER, 'rel_object-marking.internal_id'],
  [CONTEXT_OBJECT_LABEL_FILTER, 'context_data.labels_ids'],
  [MEMBERS_USER_FILTER, 'user_id'],
  [MEMBERS_GROUP_FILTER, 'group_ids'],
  [MEMBERS_ORGANIZATION_FILTER, 'organization_ids'],
]);

/**
 * Return a filterGroup where all special keys (rel refs) have been converted from frontend format to backend format
 * @param filterGroup
 */
export const convertRelationRefsFilterKeys = (filterGroup: FilterGroup): FilterGroup => {
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
        .map((key) => (STIX_CORE_RELATIONSHIPS.includes(key) ? buildRefRelationKey(key, '*') : key)) // convert relation keys -> rel_X or keep key
        .map((key) => (INTERNAL_RELATIONSHIPS.includes(key) ? buildRefRelationKey(key, '*') : key)) // convert internal relation keys -> rel_X or keep key
        .map((key) => [key, schemaRelationsRefDefinition.getDatabaseName(key) ?? '']) // fetch eventual ref database names
        .map(([key, name]) => (name ? buildRefRelationKey(name, '*') : key)); // convert databaseName if exists or keep initial key if not
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
  const convertedRelationsNames = relationNames.map((relationName) => `${REL_INDEX_PREFIX}${relationName}`);
  convertedRelationsNames.push(`${REL_INDEX_PREFIX}*`); // means 'all the relations'
  return convertedRelationsNames;
};

/**
 * Extract the filter keys values of a FilterGroup
 */
export const extractFilterKeyValues = (filterKey: string, filterGroup: FilterGroup) => {
  const values: string[] = [];
  const filtersResult = { ...filterGroup };
  filtersResult.filters.forEach((filter) => {
    const { key } = filter;
    const arrayKeys = Array.isArray(key) ? key : [key];
    if (arrayKeys.includes(filterKey)) {
      values.push(...filter.values);
    }
  });
  filtersResult.filterGroups.forEach((fg) => {
    const vals = extractFilterKeyValues(filterKey, fg);
    values.push(...vals);
  });
  return values;
};

/**
 * Replace @me by the user id in filter whose values can contain user ids, and replace eventual label values with label ids
 */
export const replaceEnrichValuesInFilters = (filterGroup: FilterGroup, userId: string, resolvedLabels: Record<string, string>): FilterGroup => {
  const newFilters = filterGroup.filters.map((filter) => {
    const { key } = filter;
    const arrayKeys = Array.isArray(key) ? key : [key];
    let newFilterValues = filter.values;
    if (arrayKeys.some((filterKey) => FILTER_KEYS_WITH_ME_VALUE.includes(filterKey))) {
      // replace @me value with the id of the user
      if (filter.values.includes(ME_FILTER_VALUE)) {
        newFilterValues = filter.values.map((v) => (v === ME_FILTER_VALUE ? userId : v));
      }
    }
    if (arrayKeys.includes(LABEL_FILTER)) {
      // replace labels values by the associated label id
      const labelValues = [];
      for (let i = 0; i < filter.values.length; i += 1) {
        const labelValue = filter.values[i];
        if (resolvedLabels[labelValue]) {
          labelValues.push(resolvedLabels[labelValue]);
        } else {
          labelValues.push(labelValue);
        }
      }
      newFilterValues = labelValues;
    }
    return {
      ...filter,
      values: newFilterValues,
    };
  });
  // recursivity on the filter groups
  let newFilterGroups: FilterGroup[] = [];
  if (filterGroup.filterGroups.length > 0) {
    newFilterGroups = filterGroup.filterGroups.map((fg) => replaceEnrichValuesInFilters(fg, userId, resolvedLabels));
  }
  return {
    ...filterGroup,
    filters: newFilters,
    filterGroups: newFilterGroups,
  };
};

let availableKeysCache: Set<string>;
const getAvailableKeys = () => {
  if (!availableKeysCache) {
    const availableAttributes = schemaAttributesDefinition.getAllAttributesNames();
    const availableRefRelations = schemaRelationsRefDefinition.getAllInputNames();
    const availableConvertedRefRelations = getConvertedRelationsNames(schemaRelationsRefDefinition.getAllDatabaseName());
    const availableConvertedStixCoreRelationships = getConvertedRelationsNames(STIX_CORE_RELATIONSHIPS);
    const availableConvertedInternalRelations = getConvertedRelationsNames(INTERNAL_RELATIONSHIPS);
    const availableConvertedMetrics = getMetricsAttributesNames();
    const availableKeys = availableAttributes
      .concat(availableRefRelations)
      .concat(availableConvertedRefRelations)
      .concat(STIX_CORE_RELATIONSHIPS)
      .concat(availableConvertedStixCoreRelationships)
      .concat(INTERNAL_RELATIONSHIPS)
      .concat(availableConvertedInternalRelations)
      .concat(SPECIAL_FILTER_KEYS)
      .concat(availableConvertedMetrics);
    availableKeysCache = new Set(availableKeys);
  }
  return availableKeysCache;
};

/**
 * Check the filter keys exist in the schema
 */
const checkFilterKeys = (filterGroup: FilterGroup) => {
  // TODO improvement: check filters keys correspond to the entity types if types is given
  const incorrectKeys = extractFilterKeys(filterGroup)
    .map((k) => k.split('.')[0]) // keep only the first part of the key to handle composed keys
    .filter((k) => !(getAvailableKeys().has(k)
      || k.startsWith(RULE_PREFIX)
      || getMetricsAttributesNames().includes(k)
    ));

  if (incorrectKeys.length > 0) {
    throw UnsupportedError('Incorrect filter keys not existing in any schema definition', { keys: incorrectKeys });
  }
};

export const checkFiltersFormat = (filterGroup: FilterGroup) => {
  // detect filters in the old format or in a bad format
  if (!isFilterGroupFormatCorrect(filterGroup)) {
    throw UnsupportedError('Incorrect filters format', { filter: JSON.stringify(filterGroup) });
  }
  // check values are in a correct syntax
  checkFilterGroupValuesSyntax(filterGroup);
};

export const checkFiltersValidity = (filterGroup: FilterGroup, noFiltersChecking = false) => {
  // check filters syntax
  checkFiltersFormat(filterGroup);
  // check filters keys exist in schema
  if (!noFiltersChecking && isFilterGroupNotEmpty(filterGroup)) {
    checkFilterKeys(filterGroup);
  }
};

const BASE_FORCE_LABEL = '{{byName}}=';
const computeFilterLabelMap = async (
  context: AuthContext,
  user: AuthUser,
  inputFilterGroup: FilterGroup,
  idsFinder: (context: AuthContext, user: AuthUser, ids: string[], opts: any) => Promise<Record<string, BasicStoreObject>>,
) => {
  const resolvedLabels: Record<string, string> = {};
  const labelFilterValues = extractFilterKeyValues(LABEL_FILTER, inputFilterGroup);
  const isLabelsByText = labelFilterValues.filter((val) => !isInternalId(val)).length > 0;
  const isForceLabel = (label: string) => label.startsWith(BASE_FORCE_LABEL);
  const prepareLabel = (label: string) => {
    return label.startsWith(BASE_FORCE_LABEL) ? label.substring(BASE_FORCE_LABEL.length) : label;
  };
  const generateId = (val: string) => idLabel(prepareLabel(val), isForceLabel(val));
  if (isLabelsByText) {
    const labelByIds = labelFilterValues.map((val) => generateId(val));
    const mapLabels = await idsFinder(context, user, labelByIds, { toMap: true, mapWithAllIds: true });
    for (let index = 0; index < labelFilterValues.length; index += 1) {
      const labelFilterValue = labelFilterValues[index];
      resolvedLabels[labelFilterValue] = mapLabels[generateId(labelFilterValue)]?.internal_id;
    }
  }
  return resolvedLabels;
};

export type FiltersIdsFinder = (context: AuthContext, user: AuthUser, ids: string[], opts: any) => Promise<Record<string, BasicStoreObject>>;
/**
 * Go through all keys in a filter group to:
 * - check that the key is available with respect to the schema, throws an Error if not
 * - convert relation refs key if any
 */
export const checkAndConvertFilters = async (
  context: AuthContext,
  user: AuthUser,
  inputFilterGroup: FilterGroup | null | undefined,
  userId: string,
  idsFinder: FiltersIdsFinder,
  opts: { noFiltersChecking?: boolean; noFiltersConvert?: boolean } = {},
) => {
  if (!inputFilterGroup) {
    return undefined;
  }
  // 01. check filters validity
  const { noFiltersChecking = false, noFiltersConvert = false } = opts;
  checkFiltersValidity(inputFilterGroup, noFiltersChecking);
  // 02. If label filtered by name, try to resolve it.
  const resolvedLabels: Record<string, string> = await computeFilterLabelMap(context, user, inputFilterGroup, idsFinder);
  // 03. replace dynamic @me value and label values
  const filterGroup = replaceEnrichValuesInFilters(inputFilterGroup, userId, resolvedLabels);
  // 04. convert relation refs
  if (!noFiltersChecking && !noFiltersConvert && isFilterGroupNotEmpty(inputFilterGroup)) {
    return convertRelationRefsFilterKeys(filterGroup);
  }
  // nothing to convert
  return filterGroup;
};

/**
 * Go through all keys in a filter group and foreach keys is in keysToReplace:
 * - replace the values of the filter by the associated id in the map
 * - if no id has been found in the map for the filter values, remove the filter
 */
export const filtersEntityIdsMappingResult = (inputFilters: FilterGroup, keysToReplace: string[], valuesIdsMap: Map<string, string | null>) => {
  let newFilters = inputFilters.filters;
  let newFilterGroups = inputFilters.filterGroups;
  if (isFilterGroupNotEmpty(inputFilters)) {
    // replace the values by their ids
    newFilters = inputFilters.filters.map((f) => {
      const key = Array.isArray(f.key) ? f.key[0] : f.key;
      if (keysToReplace.includes(key)) {
        if (key === INSTANCE_REGARDING_OF) {
          const valuesIds = f.values.filter((v) => v.key === 'id').map((v) => v.values).flat();
          const resolvedValuesIds = valuesIds.map((v) => valuesIdsMap.get(v)).filter((v) => !!v);
          if (resolvedValuesIds.length > 0) {
            // eslint-disable-next-line no-param-reassign
            f.values = [
              ...f.values.filter((v) => v.key !== 'id'),
              { key: 'id', values: resolvedValuesIds },
            ];
          } else {
            // eslint-disable-next-line no-param-reassign
            f.values = [
              ...f.values.filter((v) => v.key !== 'id'),
            ];
          }
        } else {
          // eslint-disable-next-line no-param-reassign
          f.values = f.values
            .map((v) => valuesIdsMap.get(v))
            .filter((v) => !!v);
        }
      }
      const shouldRemoveFilter = f.values.length === 0 && f.operator && !['nil', 'not_nil'].includes(f.operator);
      if (shouldRemoveFilter) { // remove filters of keysToReplace with values not resolved
        return null;
      }
      return f;
    }).filter((f) => !!f);
    newFilterGroups = inputFilters.filterGroups.map((fg) => filtersEntityIdsMappingResult(fg, keysToReplace, valuesIdsMap));
  }
  return {
    ...inputFilters,
    filters: newFilters,
    filterGroups: newFilterGroups,
  };
};

// TODO: remove when dynamicFrom & dynamicTo are removed from widgets and only handled in filters
export const addDynamicFromAndToToFilters = (args: any): FilterGroup | undefined | null => {
  const { filters, dynamicFrom, dynamicTo } = args;
  let finalFilters = filters;
  if (dynamicFrom && isFilterGroupNotEmpty(dynamicFrom)) {
    finalFilters = addFilter(finalFilters, RELATION_DYNAMIC_FROM_FILTER, dynamicFrom);
  }
  if (dynamicTo && isFilterGroupNotEmpty(dynamicTo)) {
    finalFilters = addFilter(finalFilters, RELATION_DYNAMIC_TO_FILTER, dynamicTo);
  }
  return finalFilters;
};
