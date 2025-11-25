import * as R from 'ramda';
import { v4 as uuid } from 'uuid';
import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import React from 'react';
import { useFormatter } from '../../components/i18n';
import type { FilterGroup as GqlFilterGroup } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';
import useAuth, { FilterDefinition } from '../hooks/useAuth';
import { capitalizeFirstLetter, displayEntityTypeForTranslation, isValidDate } from '../String';
import { FilterRepresentative } from '../../components/filters/FiltersModel';
import { isEmptyField, uniqueArray } from '../utils';
import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from './filtersHelpers-types';
import { dateFiltersValueForDisplay } from '../Time';
import { RELATIONSHIP_WIDGETS_TYPES } from '../widget/widgetUtils';

//----------------------------------------------------------------------------------------------------------------------

export type { FilterGroup as GqlFilterGroup } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';

export interface FilterSearchContext {
  entityTypes: string[]
  elementId?: string[]
  connectorsScope?: boolean
  elementType?: string
}

export type FiltersRestrictions = {
  preventLocalModeSwitchingFor?: string[], // filter keys whose local mode can't be changed
  preventRemoveFor?: string[], // filter keys whose filter can't be removed
  preventFilterValuesEditionFor?: Map<string, string[]>, // Map<filter key, values[]> indicating the not removable value for the given filter key
};

export const emptyFilterGroup = {
  mode: 'and',
  filters: [],
  filterGroups: [],
};

//----------------------------------------------------------------------------------------------------------------------

export const SELF_ID = 'SELF_ID';
export const SELF_ID_VALUE = 'CURRENT ENTITY';

export const ME_FILTER_VALUE = '@me';

// 'within' operator filter constants
export const DEFAULT_WITHIN_FILTER_VALUES = ['now-1d', 'now'];

export const FiltersVariant = {
  list: 'list',
  dialog: 'dialog',
};

const NOT_CLEANABLE_FILTER_KEYS = ['entity_type', 'authorized_members.id', 'user_id', 'internal_id', 'entity_id', 'ids', 'bulkSearchKeywords'];

const pirScoreFilterDefinition = (pirId: string) => ({
  filterKey: `pir_score.${pirId}`,
  label: 'PIR Score',
  multiple: false,
  type: 'integer',
  subFilters: [],
  subEntityTypes: [],
  elementsForFilterValuesSearch: [],
});

const lastPirScoreDateFilterDefinition = (pirId: string) => ({
  filterKey: `last_pir_score_date.${pirId}`,
  label: 'Last PIR Score date',
  multiple: false,
  type: 'date',
  subFilters: [],
  subEntityTypes: [],
  elementsForFilterValuesSearch: [],
});

// filters which possible values are entity types or relationship types
export const entityTypesFilters = [
  'entity_type',
  'fromTypes',
  'toTypes',
  'relationship_type', // TODO to remove because is entity_type
  'contextEntityType',
  'elementWithTargetTypes',
  'type', // regardingOf subfilter
  'x_opencti_main_observable_type',
  'main_entity_type', // for DeleteOperation
  'exclusion_list_entity_types',
];

// context filters for audits (filters on the entity involved in an activity/knowledge event)
export const contextFilters = [
  'contextCreator',
  'contextCreatedBy',
  'contextEntityId',
  'contextEntityType',
  'contextObjectLabel',
  'contextObjectMarking',
];

// filters available in stix filtering (streams, playbooks, triggers)
export const stixFilters = [
  'entity_type',
  'workflow_id',
  'objectAssignee',
  'objects',
  'objectMarking',
  'objectLabel',
  'creator_id',
  'createdBy',
  'priority',
  'severity',
  'x_opencti_score',
  'x_opencti_detection',
  'revoked',
  'confidence',
  'indicator_types',
  'pattern_type',
  'pattern',
  'x_opencti_main_observable_type',
  'fromId',
  'toId',
  'fromTypes',
  'toTypes',
  'representative',
  'x_opencti_cisa_kev',
  'x_opencti_epss_score',
  'x_opencti_epss_percentile',
  'x_opencti_cvss_base_score',
  'x_opencti_cvss_base_severity',
  'report_types',
  'response_types',
  'information_types',
  'takedown_types',
  'note_types',
  'incident_type',
];

//----------------------------------------------------------------------------------------------------------------------
// utilities

const getStringFilterKey = (key: string | string[]): string => {
  return Array.isArray(key) ? key[0] : key;
};

export const isFilterGroupNotEmpty = (filterGroup?: FilterGroup | null) => {
  return !!(
    filterGroup
    && (filterGroup.filters?.length > 0 || filterGroup.filterGroups?.length > 0)
  );
};

export const isFilterFormatCorrect = (stringFilters: string): boolean => {
  const filters = JSON.parse(stringFilters);
  return filters.mode && filters.filters && filters.filterGroups;
};

export const isUniqFilter = (key: string, filterKeysSchema: Map<string, Map<string, FilterDefinition>>) => {
  const filterDefinition = filterKeysSchema.get('Stix-Core-Object')?.get(key);
  return !!(filterDefinition && ['boolean', 'date', 'integer', 'float'].includes(filterDefinition.type));
};

// basic text filters are filters of type string or text that are not entity types filters
// i.e. filters whose values are not pickable from a list and should be entered manually
export const isBasicTextFilter = (
  filterDefinition: FilterDefinition | undefined,
) => {
  return filterDefinition
    && (filterDefinition.type === 'string' || filterDefinition.type === 'text')
    && !entityTypesFilters.includes(filterDefinition.filterKey);
};

export const isNumericFilter = (
  filterType?: string,
) => {
  return filterType === 'integer' || filterType === 'float';
};

// return the values of the filters of a specific key among a filters list
export const findFilterFromKey = (
  filters: Filter[],
  key: string,
  operator = 'eq',
) => {
  for (const filter of filters) {
    if (filter.key === key) {
      if (filter.operator === operator) {
        return filter;
      }
    }
  }
  return null;
};

export const findFiltersFromKeys = (
  filters: Filter[],
  keys: string[],
  operator = 'eq',
): Filter[] => {
  const result = [];
  for (const filter of filters) {
    if (keys.includes(filter.key)) {
      if (!filter.operator || filter.operator === operator) {
        result.push(filter);
      }
    }
  }
  return result;
};

export const findFilterIndexFromKey = (
  filters: Filter[],
  key: string,
  operator?: string,
) => {
  for (let i = 0; i < filters.length; i += 1) {
    const filter = filters[i];
    if (filter.key === key) {
      if (operator && filter.operator === operator) {
        return i;
      }
      if (!operator) {
        return i;
      }
    }
  }
  return null;
};

// create a new filter: filters AND new filter built with (key, value, operator, mode)
export const addFilter = (
  filters: FilterGroup | undefined,
  key: string,
  value: string | string[],
  operator = 'eq',
  mode = 'or',
): FilterGroup | undefined => {
  const filterFromParameters = {
    key,
    values: Array.isArray(value) ? value : [value],
    operator,
    mode,
  };
  return {
    mode: 'and',
    filters: [filterFromParameters],
    filterGroups: filters && isFilterGroupNotEmpty(filters) ? [filters] : [],
  };
};

// remove filter with key=entity_type and values contains 'all'
// because in this case we want everything, so no need for filters
export const removeEntityTypeAllFromFilterGroup = (inputFilters?: FilterGroup) => {
  if (inputFilters && isFilterGroupNotEmpty(inputFilters)) {
    const { filters, filterGroups } = inputFilters;
    const newFilters = filters.filter((f) => !(f.key === 'entity_type' && f.values.includes('all')));
    const newFilterGroups = filterGroups.map((group) => removeEntityTypeAllFromFilterGroup(group)) as FilterGroup[];
    return {
      ...inputFilters,
      filters: newFilters,
      filterGroups: newFilterGroups,
    };
  }
  return inputFilters;
};

// fetch the entity type filters possible values of first and second levels
// and remove Observable if the filters target only some sub observable types
// exemple: Observable AND (Domain-Name) --> [Domain-Name]
// exemple: Domain-Name OR Observable --> [Domain-Name, Observable]
// exemple: Stix-Domain-Object AND (Malware OR (Country AND City)) --> [Stix-Domain-Object, Malware]
export const getEntityTypeTwoFirstLevelsFilterValues = (
  filters?: FilterGroup,
  observableTypes?: string[],
  domainObjectTypes?: string [],
): string[] => {
  if (!filters) {
    return [];
  }
  let firstLevelValues = findFiltersFromKeys(filters.filters, ['entity_type'], 'eq')
    .map(({ values }) => values)
    .flat();
  if (filters.filterGroups.length > 0) {
    const subFiltersSeparatedWithAnd = filters.filterGroups
      .filter((fg) => fg.mode === 'and' || (fg.mode === 'or' && fg.filters.length === 1))
      .map((fg) => fg.filters)
      .flat();
    if (subFiltersSeparatedWithAnd.length > 0) {
      const secondLevelValues = findFiltersFromKeys(subFiltersSeparatedWithAnd, ['entity_type'], 'eq')
        .map(({ values }) => values)
        .flat();
      if (secondLevelValues.length > 0) {
        if (filters.mode === 'and') {
          // if all second values are observables sub types : remove observable from firstLevelValue
          if (secondLevelValues.every((type) => observableTypes?.includes(type))) {
            firstLevelValues = firstLevelValues.filter((type) => type !== 'Stix-Cyber-Observable');
          }
          if (secondLevelValues.every((type) => domainObjectTypes?.includes(type))) {
            firstLevelValues = firstLevelValues.filter((type) => type !== 'Stix-Domain-Object');
          }
        }
        return [...firstLevelValues, ...secondLevelValues];
      }
    }
    if (filters.mode === 'or') {
      return [];
    }
  }
  return firstLevelValues;
};

// construct filters and options for widgets
export const buildFiltersAndOptionsForWidgets = (
  inputFilters: FilterGroup | undefined | null,
  opts: { removeTypeAll?: boolean, startDate?: string | null, endDate?: string | null, dateAttribute?: string, isKnowledgeRelationshipWidget?: boolean } = {},
) => {
  const { removeTypeAll = false, startDate = null, endDate = null, dateAttribute = 'created_at', isKnowledgeRelationshipWidget = false } = opts;
  let filters = inputFilters ?? undefined;
  // remove 'all' in filter with key=entity_type
  if (removeTypeAll) {
    filters = removeEntityTypeAllFromFilterGroup(filters);
  }
  // handle startDate and endDate options
  const dateFiltersContent = [];
  if (startDate) {
    dateFiltersContent.push({
      key: dateAttribute,
      values: [startDate],
      operator: 'gt',
      mode: 'or',
    });
  }
  if (endDate) {
    dateFiltersContent.push({
      key: dateAttribute,
      values: [endDate],
      operator: 'lt',
      mode: 'or',
    });
  }
  if (dateFiltersContent.length > 0) {
    filters = {
      mode: 'and',
      filters: dateFiltersContent,
      filterGroups: filters && isFilterGroupNotEmpty(filters) ? [filters] : [],
    };
  }
  if (isKnowledgeRelationshipWidget) {
    filters = addFilter(filters, 'entity_type', RELATIONSHIP_WIDGETS_TYPES);
  }
  return { filters };
};

export const useBuildFiltersForTemplateWidgets = () => {
  // fetch not allowed markings for content widgets
  const { me } = useAuth();
  const allowedMarkings = me.allowed_marking ?? [];
  const maxShareableMarkings = me.max_shareable_marking ?? [];

  const buildFiltersForTemplateWidgets = (
    inputFilters: string | undefined | null,
    containerId: string,
    maxContentMarkingsIds: string[],
  ) => {
    // replace SELF_ID
    let filters = inputFilters ? JSON.parse(inputFilters.replace(SELF_ID, containerId)) : undefined;
    // restrict markings
    const maxContentMarkings = allowedMarkings.filter((m) => maxContentMarkingsIds.includes(m.id));
    const notAllowedMarkingIds = allowedMarkings
      .filter((def) => {
        const maxMarkingsOfType = [...maxShareableMarkings, ...maxContentMarkings].filter((marking) => marking.definition_type === def.definition_type);
        return isEmptyField(maxMarkingsOfType) || maxMarkingsOfType.some((maxMarking) => maxMarking.x_opencti_order < def.x_opencti_order);
      })
      .map((m) => m.id);
    if (notAllowedMarkingIds.length > 0) {
      filters = addFilter(filters, 'objectMarking', notAllowedMarkingIds, 'not_eq', 'and');
    }
    return filters;
  };

  return { buildFiltersForTemplateWidgets };
};

// return the i18n label corresponding to a filter value
export const filterValue = (filterKey: string, value?: string | null, filterType?: string, filterOperator?: string) => {
  const { t_i18n, nsd, smhd } = useFormatter();
  if (filterKey === 'regardingOf' || filterKey === 'dynamicRegardingOf' || filterKey === 'dynamic' || filterKey === 'dynamicFrom' || filterKey === 'dynamicTo') {
    return JSON.stringify(value);
  }
  if (
    value
    && (filterType === 'boolean' || filterType === 'enum')
  ) {
    return t_i18n(value);
  }
  if (filterKey === 'x_opencti_negative') {
    return t_i18n(value === 'true' ? 'False positive' : 'True positive');
  }
  if (value && entityTypesFilters.includes(filterKey)) {
    return value === 'all'
      ? t_i18n('entity_All')
      : t_i18n(displayEntityTypeForTranslation(value));
  }
  if (filterType === 'date') {
    if (filterOperator === 'within' && !isValidDate(value)) {
      return value;
    }
    const dateConvertor = filterOperator === 'within' ? smhd : nsd;
    return dateConvertor(dateFiltersValueForDisplay(value, filterOperator));
  }
  if (filterKey === 'relationship_type' || filterKey === 'type') {
    return t_i18n(`relationship_${value}`);
  }
  return value;
};

export const isFilterEditable = (filtersRestrictions: FiltersRestrictions | undefined, filterKey: string, filterValues: string[]) => {
  return !(filtersRestrictions?.preventFilterValuesEditionFor
    && Array.from(filtersRestrictions.preventFilterValuesEditionFor.keys() ?? []).includes(filterKey)
    && filtersRestrictions.preventFilterValuesEditionFor.get(filterKey)?.some((v) => filterValues.includes(v)));
};

//----------------------------------------------------------------------------------------------------------------------
// Serialization
// TODO:
//  these functions are used to sanitize the keys inside filters before serialization and saving into backend
//  This is due to format inconsistencies between back and front formats and will be unnecessary once fixed.

export const sanitizeFiltersStructure = (filterGroup: FilterGroup): FilterGroup => ({
  ...filterGroup,
  filters: (filterGroup.filters || []).filter(
    (filter) => Array.isArray(filter.values) && filter.values.length > 0,
  ),
});

// when a filter group is serialized, we need to make sure the keys are all arrays as per graphql TS typing emission
// GQL input coercion allows to use non-array value of same type as inside the array
// but when we serialize (stringify) filters they end up parsed inside the backend, that expects strictly arrays
// --> saved filters MUST be properly sanitized
export const sanitizeFilterGroupKeysForBackend = (
  filterGroup: FilterGroup,
): GqlFilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup?.filters?.filter((f) => f.values.length > 0 || ['nil', 'not_nil'].includes(f.operator ?? 'eq'))
      .map((f) => {
        const transformFilter = {
          ...f,
          key: Array.isArray(f.key) ? f.key : [f.key],
        };
        delete transformFilter.id;
        return transformFilter;
      }),
    filterGroups: filterGroup?.filterGroups?.map((fg) => sanitizeFilterGroupKeysForBackend(fg)),
  } as GqlFilterGroup;
};

// reverse operation of sanitizeFilterGroupKeysForBackend
export const sanitizeFilterGroupKeysForFrontend = (
  filterGroup: GqlFilterGroup,
): FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup?.filters?.map((f) => ({
      ...f,
      id: uuid(),
      key: Array.isArray(f.key) ? f.key[0] : f.key,
      values: f.values.map((v) => v || 'todo: delete this'),
    })),
    filterGroups: filterGroup?.filterGroups?.map((fg) => sanitizeFilterGroupKeysForFrontend(fg)),
  } as FilterGroup;
};

/**
 * Turns a FilterGroup (frontend format, i.e. with single keys) into the backend format (key is an array)
 * and stringify it, ready to be saved in backend.
 * @param filterGroup
 */
export const serializeFilterGroupForBackend = (
  filterGroup?: FilterGroup | null,
): string => {
  if (!filterGroup) {
    return JSON.stringify(emptyFilterGroup);
  }
  return JSON.stringify(sanitizeFilterGroupKeysForBackend(filterGroup));
};

/**
 * Parse a filterGroup as given by the backend (backend format, i.e. with array keys),
 * And turns it into the frontend format (single key).²
 * @param filterGroup
 */
export const deserializeFilterGroupForFrontend = (
  filterGroup?: GqlFilterGroup | string | null,
): FilterGroup | null => {
  if (!filterGroup) {
    return null;
  }
  let filters: GqlFilterGroup;
  if (typeof filterGroup === 'string') {
    filters = JSON.parse(filterGroup) as GqlFilterGroup;
  } else {
    filters = filterGroup;
  }
  return sanitizeFilterGroupKeysForFrontend(filters);
};

// Dashboard manifests are complex objects with filters deeply nested in widgets configurations
// (de)serialization is a bit more complex
// We use any here and use it when manipulating the manifest or internal fields
// eslint-disable-next-line @typescript-eslint/no-explicit-any
type AnyForDashboardManifest = any;

/**
 * Serialize a complex dashboard manifest, sanitizing all filters inside the manifest before.
 * @param manifest
 */
export const serializeDashboardManifestForBackend = (
  manifest: AnyForDashboardManifest,
): string => {
  const newWidgets: Record<string, AnyForDashboardManifest> = {};
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    newWidgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map(
        (selection: AnyForDashboardManifest) => ({
          ...selection,
          filters: selection.filters
            ? sanitizeFilterGroupKeysForBackend(selection.filters)
            : undefined,
          dynamicFrom: selection.dynamicFrom
            ? sanitizeFilterGroupKeysForBackend(selection.dynamicFrom)
            : undefined,
          dynamicTo: selection.dynamicTo
            ? sanitizeFilterGroupKeysForBackend(selection.dynamicTo)
            : undefined,
        }),
      ),
    };
  });

  return JSON.stringify({
    ...manifest,
    widgets: newWidgets,
  });
};

export const deserializeDashboardManifestForFrontend = (
  manifestStr: string,
): AnyForDashboardManifest => {
  const manifest = JSON.parse(manifestStr);
  const newWidgets: Record<string, AnyForDashboardManifest> = {};
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    newWidgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map(
        (selection: AnyForDashboardManifest) => ({
          ...selection,
          filters: selection.filters
            ? sanitizeFilterGroupKeysForFrontend(selection.filters)
            : undefined,
          dynamicFrom: selection.dynamicFrom
            ? sanitizeFilterGroupKeysForFrontend(selection.dynamicFrom)
            : undefined,
          dynamicTo: selection.dynamicTo
            ? sanitizeFilterGroupKeysForFrontend(selection.dynamicTo)
            : undefined,
        }),
      ),
    };
  });

  return {
    ...manifest,
    widgets: newWidgets,
  };
};

//----------------------------------------------------------------------------------------------------------------------

// add a filter (k, id, op) in a filterGroup smartly, for usage in forms
// note that we're only dealing with one-level filterGroup (no nested), so we just update the 1st level filters list
export const constructHandleAddFilter = (
  filters: FilterGroup | undefined | null,
  k: string,
  id: string | null,
  filterKeysSchema: Map<string, Map<string, FilterDefinition>>,
  op = 'eq',
) => {
  // if the filter key is already used, update it
  if (filters && findFilterFromKey(filters.filters, k, op)) {
    const filter = findFilterFromKey(filters.filters, k, op);
    let newValues: FilterValue[] = [];
    if (id !== null) {
      newValues = isUniqFilter(k, filterKeysSchema)
        ? [id]
        : R.uniq([...(filter?.values ?? []), id]);
    }
    const newFilterElement = {
      key: k,
      values: newValues,
      operator: op,
      mode: 'or',
    };
    return {
      ...filters,
      filters: [
        ...filters.filters.filter((f) => f.key !== k || f.operator !== op), // remove filter with k as key
        newFilterElement, // add new filter
      ],
    };
  }
  // new filter key, add it ot the list
  const newFilterElement = {
    key: k,
    values: id !== null ? [id] : [],
    operator: op ?? 'eq',
    mode: 'or',
  };
  return filters
    ? {
      ...filters,
      filters: [...filters.filters, newFilterElement], // add new filter
    }
    : {
      mode: 'and',
      filterGroups: [],
      filters: [newFilterElement],
    };
};

// remove a filter (k, op, id) in a filterGroup smartly, for usage in forms
// if the filter ends up empty, return undefined
export const constructHandleRemoveFilter = (filters: FilterGroup | undefined | null, k: string, op = 'eq') => {
  if (filters) {
    const newBaseFilters = {
      ...filters,
      filters: filters.filters.filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
    };
    return isFilterGroupNotEmpty(newBaseFilters) ? newBaseFilters : emptyFilterGroup;
  }
  return undefined;
};

// switch the mode inside a specific filter
export const filtersAfterSwitchLocalMode = (filters: FilterGroup | undefined | null, localFilter: Filter) => {
  if (filters) {
    const filterIndex = findFilterIndexFromKey(
      filters.filters,
      localFilter.key,
      localFilter.operator,
    );
    if (filterIndex !== null) {
      const newFiltersContent = [...filters.filters];
      newFiltersContent[filterIndex] = {
        ...localFilter,
        mode: localFilter.mode === 'and' ? 'or' : 'and',
      };
      return {
        ...filters,
        filters: newFiltersContent,
      };
    }
  }
  return undefined;
};

export const getDefaultOperatorFilter = (
  filterDefinition?: FilterDefinition,
) => {
  if (!filterDefinition) {
    return 'eq';
  }
  const { type } = filterDefinition;
  if (type === 'date') {
    return 'within';
  }
  if (isNumericFilter(type)) {
    return 'gt';
  }
  if (type === 'boolean') {
    return 'eq';
  }
  if (isBasicTextFilter(filterDefinition)) {
    if (filterDefinition.type === 'string') {
      return 'starts_with';
    } if (filterDefinition.type === 'text') {
      if (type === 'text') {
        return 'search';
      }
    } else {
      throw Error(`A basic text filter is of type string or text, not ${filterDefinition.type}`);
    }
  }
  return 'eq';
};

/**
 * Get the possible operator for a given key/subkey.
 * Subkeys are nested inside special filter that combine several fields (filter values is not a string[] but object[])
 */
export const getAvailableOperatorForFilterSubKey = (filterKey: string, subKey: string): string[] => {
  if (filterKey === 'regardingOf' || filterKey === 'dynamicRegardingOf') {
    if (subKey === 'relationship_type') { // As first element of the filter
      return ['eq', 'not_eq'];
    }
    return [];
  }

  return ['eq', 'not_eq', 'nil', 'not_nil'];
};

/**
 * Operators are restricted depending on the filter definition
 * @param filterDefinition
 */
export const getAvailableOperatorForFilterKey = (
  filterDefinition: FilterDefinition | undefined,
): string[] => {
  if (!filterDefinition) {
    return ['eq'];
  }
  if (filterDefinition.filterKey === 'connectedToId') { // instance trigger filter
    return ['eq'];
  }
  const { type: filterType } = filterDefinition;
  if (filterType === 'date') {
    return ['gt', 'gte', 'lt', 'lte', 'nil', 'not_nil', 'within'];
  }
  if (isNumericFilter(filterType)) {
    return ['gt', 'gte', 'lt', 'lte'];
  }
  if (filterType === 'boolean') {
    return ['eq', 'not_eq'];
  }
  if (isBasicTextFilter(filterDefinition)) {
    if (filterDefinition.type === 'string') {
      return ['eq', 'not_eq', 'nil', 'not_nil', 'contains', 'not_contains',
        'starts_with', 'not_starts_with', 'ends_with', 'not_ends_with', 'search'];
    } if (filterDefinition.type === 'text') {
      if (filterDefinition.type === 'text') {
        return ['search', 'nil', 'not_nil'];
      }
    } else {
      throw Error(`A basic text filter is of type string or text, not ${filterDefinition.type}`);
    }
  }

  return ['eq', 'not_eq', 'nil', 'not_nil']; // vocabulary or id
};

export const getAvailableOperatorForFilter = (
  filterDefinition: FilterDefinition | undefined,
  subKey?: string,
): string[] => {
  if (filterDefinition && subKey) return getAvailableOperatorForFilterSubKey(filterDefinition.filterKey, subKey);
  return getAvailableOperatorForFilterKey(filterDefinition);
};

export const useFetchFilterKeysSchema = () => {
  let filterKeysSchema: Map<string, Map<string, FilterDefinition>>;

  try {
    filterKeysSchema = useAuth().schema.filterKeysSchema;
  } catch (_e) {
    filterKeysSchema = new Map();
  }
  return filterKeysSchema;
};

export const useBuildFilterKeysMapFromEntityType = (entityTypes = ['Stix-Core-Object']): Map<string, FilterDefinition> => {
  const { filterKeysSchema } = useAuth().schema;
  // 1. case one entity type
  if (entityTypes.length === 1) {
    return filterKeysSchema.get(entityTypes[0]) ?? new Map();
  }
  // 2. case several entity types
  const filterKeysMap = new Map();
  entityTypes.forEach((entityType) => {
    const currentMap = filterKeysSchema.get(entityType) ?? new Map();
    currentMap.forEach((value, key) => {
      const valueToSet = filterKeysMap.has(key)
        ? { ...value, subEntityTypes: filterKeysMap.get(key).subEntityTypes.concat([entityType]) }
        : value;
      filterKeysMap.set(key, valueToSet);
    });
  });
  // add entity_type filter if several types are given (entity_type filter already present for abstract types)
  if (entityTypes.length > 0) {
    filterKeysMap.set('entity_type', {
      filterKey: 'entity_type',
      type: 'string',
      label: 'Entity type',
      multiple: true,
      subEntityTypes: entityTypes,
      elementsForFilterValuesSearch: [],
    });
  }
  return filterKeysMap;
};

export const useAvailableFilterKeysForEntityTypes = (entityTypes: string[]) => {
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  return uniqueArray(filterKeysMap.keys() ?? []);
};

const isFilterKeyAvailable = (key: string, availableFilterKeys: string[]) => {
  const completedAvailableFilterKeys = availableFilterKeys.concat(NOT_CLEANABLE_FILTER_KEYS);
  return completedAvailableFilterKeys.includes(key) || key.startsWith('pir_score') || key.startsWith('last_pir_score_date');
};

export const removeIdFromFilterGroupObject = (filters?: FilterGroup | null): FilterGroup | undefined => {
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters.mode,
    filters: filters.filters
      .filter((f) => ['nil', 'not_nil'].includes(f.operator ?? 'eq') || f.values.length > 0)
      .map((f) => {
        const newFilter = { ...f };
        delete newFilter.id;
        if (newFilter.key === 'dynamicRegardingOf') { // remove id from filters contained in dynamic values of dynamicRegardingOf filter
          const dynamicValues = newFilter.values.filter((value) => value.key === 'dynamic')
            .map((dynamic) => ({
              ...dynamic,
              values: dynamic.values.map((dynamicFilter: FilterGroup) => removeIdFromFilterGroupObject(dynamicFilter)),
            }));
          const relationshipTypeValues = newFilter.values.filter((value) => value.key === 'relationship_type');
          newFilter.values = [...dynamicValues, ...relationshipTypeValues];
        }
        return newFilter;
      }),
    filterGroups: filters.filterGroups.map((group) => removeIdFromFilterGroupObject(group)) as FilterGroup[],
  };
};

const notCleanableFilterKeys = ['ids', 'entity_type', 'authorized_members.id', 'user_id', 'internal_id', 'entity_id'];

// TODO use useRemoveIdAndIncorrectKeysFromFilterGroupObject instead when all the calling files are in pure function
export const removeIdAndIncorrectKeysFromFilterGroupObject = (filters: FilterGroup | null | undefined, availableFilterKeys: string[]): FilterGroup | undefined => {
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters.mode,
    filters: filters.filters
      .filter((f) => isFilterKeyAvailable(f.key, availableFilterKeys))
      .filter((f) => ['nil', 'not_nil'].includes(f.operator ?? 'eq') || f.values.length > 0)
      .map((f) => {
        const newFilter = { ...f };
        delete newFilter.id;
        if (newFilter.key === 'dynamicRegardingOf') { // remove id from filters contained in dynamic values of dynamicRegardingOf filter
          const dynamicValues = newFilter.values.filter((value) => value.key === 'dynamic')
            .map((dynamic) => ({
              ...dynamic,
              values: dynamic.values.map((dynamicFilter: FilterGroup) => removeIdFromFilterGroupObject(dynamicFilter)),
            }));
          const relationshipTypeValues = newFilter.values.filter((value) => value.key === 'relationship_type');
          newFilter.values = [...dynamicValues, ...relationshipTypeValues];
        }
        return newFilter;
      }),
    filterGroups: filters.filterGroups.map((group) => removeIdAndIncorrectKeysFromFilterGroupObject(group, availableFilterKeys)) as FilterGroup[],
  };
};

export const useRemoveIdAndIncorrectKeysFromFilterGroupObject = (filters?: FilterGroup | null, entityTypes = ['Stix-Core-Object']): FilterGroup | undefined => {
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(entityTypes).concat(notCleanableFilterKeys);
  return removeIdAndIncorrectKeysFromFilterGroupObject(filters, availableFilterKeys);
};

export const useBuildEntityTypeBasedFilterContext = (
  entityTypeParam: string | string[],
  filters: FilterGroup | undefined,
  excludedEntityTypeParam?: string | string[] | undefined,
  entityTypesContext?: string[],
): FilterGroup => {
  const entityTypes = Array.isArray(entityTypeParam) ? entityTypeParam : [entityTypeParam];
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, entityTypesContext ?? entityTypes);
  const entityTypeFilter = { key: 'entity_type', values: entityTypes, operator: 'eq', mode: 'or' };
  const entityTypeFilters = [entityTypeFilter];
  if (excludedEntityTypeParam && excludedEntityTypeParam.length > 0) {
    const excludedEntityTypes = Array.isArray(excludedEntityTypeParam) ? excludedEntityTypeParam : [excludedEntityTypeParam];
    const excludedEntityTypeFilter = { key: 'entity_type', values: excludedEntityTypes, operator: 'not_eq', mode: 'or' };
    entityTypeFilters.push(excludedEntityTypeFilter);
  }
  return {
    mode: 'and',
    filters: entityTypeFilters,
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
};

export const getFilterDefinitionFromFilterKeysMap = (
  key: string | string[],
  filterKeysMap: Map<string, FilterDefinition>,
): FilterDefinition | undefined => {
  const filterKey = getStringFilterKey(key);
  if (filterKey.startsWith('pir_score.')) {
    const pirId = filterKey.split('.')[1];
    return pirScoreFilterDefinition(pirId);
  }
  if (filterKey.startsWith('last_pir_score_date.')) {
    const pirId = filterKey.split('.')[1];
    return lastPirScoreDateFilterDefinition(pirId);
  }
  return filterKeysMap.get(filterKey);
};

export const useFilterDefinition = (
  key: string | string[],
  entityTypes = ['Stix-Core-Object', 'stix-core-relationship'],
  subKey?: string,
): FilterDefinition | undefined => {
  const filterKey = getStringFilterKey(key);
  if (filterKey.startsWith('pir_score.')) {
    const pirId = filterKey.split('.')[1];
    return pirScoreFilterDefinition(pirId);
  }
  if (filterKey.startsWith('last_pir_score_date.')) {
    const pirId = filterKey.split('.')[1];
    return lastPirScoreDateFilterDefinition(pirId);
  }
  const filterDefinition = useBuildFilterKeysMapFromEntityType(entityTypes).get(filterKey);
  if (subKey) {
    const subFilterDefinition = filterDefinition?.subFilters
      ? filterDefinition.subFilters.filter((subFilter: FilterDefinition) => subFilter.filterKey === subKey)
      : undefined;
    if (subFilterDefinition && subFilterDefinition.length > 0) {
      return subFilterDefinition[0];
    }
    throw Error(`The ${subKey} sub-filter doesn't exist for the ${filterKey} filter`);
  }
  return filterDefinition;
};

export const getDefaultFilterObject = (
  filterKey: string,
  filterDefinition?: FilterDefinition,
  values?: FilterValue[],
  mode?: string,
): Filter => {
  return {
    id: uuid(),
    key: filterKey,
    operator: getDefaultOperatorFilter(filterDefinition),
    values: values ?? [],
    mode: mode ?? 'or',
  };
};

export const useGetDefaultFilterObject = (
  filterKeys: string[],
  entityTypes: string[],
  values?: FilterValue[],
  mode?: string,
) => {
  const filtersDefinition = filterKeys.map((key) => useFilterDefinition(key, entityTypes));
  return (filtersDefinition
    .filter((def) => def) as FilterDefinition[])
    .map((def) => getDefaultFilterObject(def.filterKey, def, values, mode));
};

export const isStixObjectTypes = [
  'fromOrToId',
  'fromId',
  'toId',
  'objects',
  'targets',
  'indicates',
  'contextEntityId',
  'id',
];

export const getSelectedOptions = (
  entitiesOptions: FilterOptionValue[],
  filterValues: string[],
  filtersRepresentativesMap: Map<string,
  FilterRepresentative>,
  t_i18n: (s: string) => string,
): FilterOptionValue[] => {
  // we try to get first the element from the search
  // and if we did not find we tried one from filterRepresentative
  // Most of the time element from search should be sufficient
  const mapFilterValues: FilterOptionValue[] = [];
  filterValues.forEach((value: string) => {
    const mapRepresentative = entitiesOptions.find((f) => f.value === value);
    if (mapRepresentative) {
      mapFilterValues.push({
        ...mapRepresentative,
        group: capitalizeFirstLetter(t_i18n('selected')),
      });
    } else if (value === SELF_ID) {
      mapFilterValues.push({
        value,
        type: 'instance',
        parentTypes: [],
        group: capitalizeFirstLetter(t_i18n('selected')),
        label: SELF_ID_VALUE,
      });
    } else {
      const filterRepresentative = filtersRepresentativesMap.get(value);
      if (filterRepresentative) {
        mapFilterValues.push({
          value,
          type: filterRepresentative?.entity_type || t_i18n('deleted'),
          parentTypes: [],
          group: capitalizeFirstLetter(t_i18n('selected')),
          label: filterRepresentative?.value ?? t_i18n('deleted'),
          color: filterRepresentative?.color ?? undefined,
        });
      }
    }
  });
  return mapFilterValues.sort((a, b) => a.label.localeCompare(b.label));
};

// filter operators that can display with an icon
export const filterOperatorsWithIcon = [
  'lt',
  'lte',
  'gt',
  'gte',
  'nil',
  'not_nil',
  'eq',
  'not_eq',
];

export const convertOperatorToIcon = (operator: string) => {
  switch (operator) {
    case 'lt':
      return <>&nbsp;&#60;</>;
    case 'lte':
      return <>&nbsp;&#8804;</>;
    case 'gt':
      return <>&nbsp;&#62;</>;
    case 'gte':
      return <>&nbsp;&#8805;</>;
    case 'eq':
      return <>&nbsp;=</>;
    case 'not_eq':
      return <>&nbsp;&#8800;</>;
    default:
      return null;
  }
};

export const extractAllFilters: (filters: FilterGroup) => Filter[] = (filters: FilterGroup) => {
  const allFilters: Filter[] = [];
  allFilters.push(...filters.filters);
  filters.filterGroups.forEach((filterGroup) => extractAllFilters(filterGroup));
  return allFilters;
};

export const cleanFilters = (filters: FilterGroup, helpers: handleFilterHelpers, types: string[], completeFilterKeysMap: Map<string, Map<string, FilterDefinition>>) => {
  const newAvailableFilterKeys = uniqueArray(types.flatMap((t) => Array.from(completeFilterKeysMap.get(t)?.keys() ?? [])));
  const allListedFilters = extractAllFilters(filters);
  const filtersToRemoveIds = allListedFilters.filter((f) => !newAvailableFilterKeys.includes(f.key)).map((f) => f.id ?? '');
  filtersToRemoveIds.forEach((id) => helpers.handleRemoveFilterById(id));
};

export const isRegardingOfFilterWarning = (
  filter: Filter,
  observablesTypes: string[],
  filtersRepresentativesMap: Map<string, FilterRepresentative>,
) => {
  if (filter.key === 'regardingOf') {
    const relationshipTypes: string[] = filter.values.filter((v) => v.key === 'relationship_type').map((f) => f.values).flat();
    const entitiesIds: string[] = filter.values.filter((v) => v.key === 'id').map((f) => f.values).flat();
    const entityTypes = entitiesIds
      .map((id) => filtersRepresentativesMap.get(id)?.entity_type)
      .filter((t) => !!t) as string[];
    if (relationshipTypes.includes('located-at')
      && entityTypes.some((type) => ['City', 'IPv4-Addr', 'IPv6-Addr'].includes(type))) {
      return true;
    } if (relationshipTypes.includes('related-to')
      && entityTypes.some((type) => [...observablesTypes, 'Stix-Cyber-Observable'].includes(type))) {
      return true;
    } if (relationshipTypes.includes('indicates')
      && entityTypes.some((type) => ['Indicator'].includes(type))) {
      return true;
    }
  }
  return false;
};

export const getFilterKeyValues = (filterKey: string, filterGroup: FilterGroup) => {
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
    const vals = getFilterKeyValues(filterKey, fg);
    values.push(...vals);
  });
  return values;
};
