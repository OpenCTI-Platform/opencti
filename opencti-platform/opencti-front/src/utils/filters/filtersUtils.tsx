import * as R from 'ramda';
import { v4 as uuid } from 'uuid';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import React from 'react';
import { useFormatter } from '../../components/i18n';
import type { FilterGroup as GqlFilterGroup } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';
import useAuth, { FilterDefinition } from '../hooks/useAuth';
import { capitalizeFirstLetter } from '../String';
import { FilterRepresentative } from '../../components/filters/FiltersModel';
import { generateUniqueItemsArray } from '../utils';
import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from './filtersHelpers-types';

//----------------------------------------------------------------------------------------------------------------------

export type { FilterGroup as GqlFilterGroup } from './__generated__/useSearchEntitiesStixCoreObjectsSearchQuery.graphql';

export interface FilterSearchContext {
  entityTypes: string[]
  elementId?: string[]
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

export const FiltersVariant = {
  list: 'list',
  dialog: 'dialog',
};

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
  'x_opencti_main_observable_type',
  'fromId',
  'toId',
  'fromTypes',
  'toTypes',
  'representative',
];

//----------------------------------------------------------------------------------------------------------------------
// utilities

export const isFilterGroupNotEmpty = (filterGroup?: FilterGroup | null) => {
  return (
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
// i.e. filters whose values are not pickable from a list but should be enter
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
  operator?: string,
) => {
  const result = [];
  for (const filter of filters) {
    if (keys.includes(filter.key)) {
      if (operator && filter.operator === operator) {
        result.push(filter);
      }
      if (!operator) {
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

// construct filters and options for widgets
export const buildFiltersAndOptionsForWidgets = (
  inputFilters: FilterGroup | undefined,
  opts: { removeTypeAll?: boolean, startDate?: string, endDate?: string, dateAttribute?: string } = {},
) => {
  const { removeTypeAll = false, startDate = null, endDate = null, dateAttribute = 'created_at' } = opts;
  let filters = inputFilters;
  // 02. remove 'all' in filter with key=entity_type
  if (removeTypeAll) {
    filters = removeEntityTypeAllFromFilterGroup(filters);
  }
  // 03. handle startDate and endDate options
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
  return {
    filters,
  };
};

// return the i18n label corresponding to a value
export const filterValue = (filterKey: string, value?: string | null, filterType?: string) => {
  const { t_i18n, nsd } = useFormatter();
  if (filterKey === 'regardingOf') {
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
      : t_i18n(
        value.toString()[0] === value.toString()[0].toUpperCase()
          ? `entity_${value.toString()}`
          : `relationship_${value.toString()}`,
      );
  }
  if (filterType === 'date') {
    return nsd(value);
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

// when a filter group is serialized, we need to make sure the keys are all arrays as per graphql TS typing emission
// GQL input coercion allows to use non-array value of same type as inside the array
// but when we serialize (stringify) filters they end up parsed inside the backend, that expects strictly arrays
// --> saved filters MUST be properly sanitized
const sanitizeFilterGroupKeysForBackend = (
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
const sanitizeFilterGroupKeysForFrontend = (
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

// forcefully add a filter into a filterGroup, no check done
export const addFilter = (
  filters: FilterGroup | undefined,
  key: string,
  value: string | string[],
  operator = 'eq',
  mode = 'or',
): FilterGroup | undefined => {
  const filterFromParameters = {
    id: uuid(),
    key,
    values: Array.isArray(value) ? value : [value],
    operator,
    mode,
  };
  if (!filters) { // Add on nothing = create a new filter
    return {
      mode,
      filters: [filterFromParameters],
      filterGroups: [],
    };
  }
  return {
    mode: filters?.mode ?? 'and',
    filters: (filters?.filters ?? []).concat([filterFromParameters]),
    filterGroups: filters?.filterGroups ?? [],
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

const defaultFilterObject: Filter = {
  id: '',
  key: '',
  values: [],
  operator: '',
  mode: 'or',
};
export const getDefaultOperatorFilter = (
  filterDefinition?: FilterDefinition,
) => {
  if (!filterDefinition) {
    return 'eq';
  }
  const { type } = filterDefinition;
  if (type === 'date') {
    return 'gte';
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
  if (filterKey === 'regardingOf') {
    if (subKey === 'id' || subKey === 'relationship_type') {
      return ['eq'];
    }
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
    return ['gt', 'gte', 'lt', 'lte', 'nil', 'not_nil'];
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
  if (filterDefinition && subKey) return getAvailableOperatorForFilterSubKey(filterDefinition?.filterKey, subKey);
  return getAvailableOperatorForFilterKey(filterDefinition);
};

export const useFetchFilterKeysSchema = () => {
  const { filterKeysSchema } = useAuth().schema;
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
  if (entityTypes.length > 0) { // add entity_type filter if several types are given (entity_type filter already present for abstract types)
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
  return generateUniqueItemsArray(filterKeysMap.keys() ?? []);
};

export const useRemoveIdAndIncorrectKeysFromFilterGroupObject = (filters?: FilterGroup | null, entityTypes = ['Stix-Core-Object']): FilterGroup | undefined => {
  const availableFilterKeys = useAvailableFilterKeysForEntityTypes(entityTypes).concat('entity_type');
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters.mode,
    filters: filters.filters
      .filter((f) => availableFilterKeys.includes(f.key))
      .filter((f) => ['nil', 'not_nil'].includes(f.operator ?? 'eq') || f.values.length > 0)
      .map((f) => {
        const newFilter = { ...f };
        delete newFilter.id;
        return newFilter;
      }),
    filterGroups: filters.filterGroups.map((group) => useRemoveIdAndIncorrectKeysFromFilterGroupObject(group, entityTypes)) as FilterGroup[],
  };
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
        return newFilter;
      }),
    filterGroups: filters.filterGroups.map((group) => removeIdFromFilterGroupObject(group)) as FilterGroup[],
  };
};

// TODO use useRemoveIdAndIncorrectKeysFromFilterGroupObject instead when all the calling files are in pure function
export const removeIdAndIncorrectKeysFromFilterGroupObject = (filters: FilterGroup | null | undefined, availableFilterKeys: string[]): FilterGroup | undefined => {
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters.mode,
    filters: filters.filters
      .filter((f) => availableFilterKeys.includes(f.key))
      .filter((f) => ['nil', 'not_nil'].includes(f.operator ?? 'eq') || f.values.length > 0)
      .map((f) => {
        const newFilter = { ...f };
        delete newFilter.id;
        return newFilter;
      }),
    filterGroups: filters.filterGroups.map((group) => removeIdAndIncorrectKeysFromFilterGroupObject(group, availableFilterKeys)) as FilterGroup[],
  };
};

export const useBuildEntityTypeBasedFilterContext = (entityTypeParam: string | string[], filters: FilterGroup | undefined): FilterGroup => {
  const entityTypes = Array.isArray(entityTypeParam) ? entityTypeParam : [entityTypeParam];
  const userFilters = useRemoveIdAndIncorrectKeysFromFilterGroupObject(filters, entityTypes);
  return {
    mode: 'and',
    filters: [
      {
        key: 'entity_type',
        values: entityTypes,
        operator: 'eq',
        mode: 'or',
      },
    ],
    filterGroups: userFilters && isFilterGroupNotEmpty(userFilters) ? [userFilters] : [],
  };
};

export const useFilterDefinition = (filterKey: string, entityTypes = ['Stix-Core-Object', 'stix-core-relationship'], subKey?: string): FilterDefinition | undefined => {
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
): Filter => {
  return {
    ...defaultFilterObject,
    id: uuid(),
    key: filterKey,
    operator: getDefaultOperatorFilter(filterDefinition),
  };
};

export const useGetDefaultFilterObject = (
  filterKeys: string[],
  entityTypes: string[],
) => {
  const filtersDefinition = filterKeys.map((key) => useFilterDefinition(key, entityTypes));
  return (filtersDefinition
    .filter((def) => def) as FilterDefinition[])
    .map((def) => getDefaultFilterObject(def.filterKey, def));
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
  entitiesOptions: OptionValue[],
  filterValues: string[],
  filtersRepresentativesMap: Map<string,
  FilterRepresentative>,
  t_i18n: (s: string) => string,
): OptionValue[] => {
  // we try to get first the element from the search
  // and if we did not find we tried one from filterReprensentative
  // Most of the time element from search should be sufficient
  const mapFilterValues: OptionValue[] = [];
  filterValues.forEach((value: string) => {
    const mapRepresentative = entitiesOptions.find((f) => f.value === value);
    if (mapRepresentative) {
      mapFilterValues.push({
        ...mapRepresentative,
        group: capitalizeFirstLetter(t_i18n('selected')),
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
  const newAvailableFilterKeys = generateUniqueItemsArray(types.flatMap((t) => Array.from(completeFilterKeysMap.get(t)?.keys() ?? [])));
  const allListedFilters = extractAllFilters(filters);
  const filtersToRemoveIds = allListedFilters.filter((f) => !newAvailableFilterKeys.includes(f.key)).map((f) => f.id ?? '');
  filtersToRemoveIds.forEach((id) => helpers.handleRemoveFilterById(id));
};
