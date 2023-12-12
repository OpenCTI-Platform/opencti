import * as R from 'ramda';
import { v4 as uuid } from 'uuid';
import { useFormatter } from '../../components/i18n';

import type { FilterGroup as GqlFilterGroup } from './__generated__/useSearchEntitiesStixCoreObjectsContainersSearchQuery.graphql';

//----------------------------------------------------------------------------------------------------------------------

export type { FilterGroup as GqlFilterGroup } from './__generated__/useSearchEntitiesStixCoreObjectsContainersSearchQuery.graphql';

export type FilterGroup = {
  mode: string;
  filters: Filter[];
  filterGroups: FilterGroup[];
};

// TODO: import from graphql generated types
export type Filter = {
  id?: string;
  key: string; // key is a string in front
  values: string[];
  operator: string;
  mode: string;
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

export const onlyGroupOrganization = ['workflow_id'];

export const directFilters = [
  'is_read',
  'channel_types',
  'pattern_type',
  'sightedBy',
  'container_type',
  'toSightingId',
  'x_opencti_negative',
  'fromId',
  'toId',
  'elementId',
  'contextEntityId',
  'note_types',
  'context',
  'trigger_type',
  'instance_trigger',
  'containers',
  'objectContains',
  'entity_type',
  'container_type',
];
export const inlineFilters = ['is_read', 'trigger_type', 'instance_trigger'];

export const integerFilters = [
  'x_opencti_base_score',
  'x_opencti_score',
  'confidence',
  'likelihood',
];

export const textFilters = [
  'name',
  'description',
  'value',
];

// filters that can have 'eq' or 'not_eq' operator
export const EqFilters = [
  'objectLabel',
  'createdBy',
  'objectMarking',
  'entity_type',
  'workflow_id',
  'malware_types',
  'incident_type',
  'context',
  'pattern_type',
  'indicator_types',
  'report_types',
  'note_types',
  'channel_types',
  'event_types',
  'sightedBy',
  'relationship_type',
  'creator_id',
  'x_opencti_negative',
  'source',
  'objects',
  'indicates',
  'targets',
  'x_opencti_main_observable_type',
  'objectAssignee',
  'objectParticipant',
  'killChainPhases',
  'x_opencti_reliability',
  'contextEntityId',
  'event_type',
  'event_scope',
  'user_id',
  'group_ids',
  'organization_ids',
];

// filters that can only have an 'eq' operator and a 'or' mode
export const filtersUsedAsApiParameters = [
  'fromId',
  'fromTypes',
  'toId',
  'toTypes',
  'elementTargetTypes',
  'elementId',
  'toSightingId',
];

// filters that represents a date, can have lt (end date) or gt (start date) operators
export const dateFilters = [
  'published',
  'created',
  'created_at',
  'modified',
  'valid_from',
  'start_time',
  'stop_time',
];

const uniqFilters = [
  'revoked',
  'x_opencti_detection',
  'x_opencti_base_score',
  'confidence',
  'likelihood',
  'x_opencti_negative',
  'x_opencti_score',
  'toSightingId',
  'based-on',
];

// filters that targets entities instances
export const entityFilters = [
  'elementId',
  'fromId',
  'toId',
  'createdBy',
  'objects',
  'indicates',
  'targets',
  'connectedToId',
  'contextEntityId',
];

export const booleanFilters = [
  'x_opencti_detection',
  'revoked',
  'is_read',
  'x_opencti_reliability',
  'instance_trigger',
];

export const entityTypesFilters = [
  'entity_type',
  'entity_types',
  'fromTypes',
  'toTypes',
  'relationship_types',
  'container_type',
  'contextEntityType',
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

export const isUniqFilter = (key: string) => uniqFilters.includes(key) || dateFilters.includes(key);

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

export const extractAllValueFromFilters = (filters: Filter[], key: string): Filter | null => {
  const extractFilter: Filter = {
    key,
    mode: 'or',
    operator: 'eq',
    values: [],
  };
  filters.forEach((filter) => {
    if (filter.key === key) {
      extractFilter.values.push(...filter.values);
    }
  });
  return extractFilter.values.length > 0 ? extractFilter : null;
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

// add entity types context in filters
export const injectEntityTypeFilterInFilterGroup = (
  filters: FilterGroup | undefined,
  type: string | string[],
): FilterGroup => {
  const entityTypeFilter: Filter = {
    id: uuid(),
    key: 'entity_type',
    values: Array.isArray(type) ? type : [type],
    operator: 'eq',
    mode: 'or',
  };
  return {
    mode: 'and',
    filters: [entityTypeFilter],
    filterGroups: filters ? [filters] : [],
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

// construct filters and options for widgets
export const buildFiltersAndOptionsForWidgets = (
  inputFilters: FilterGroup | undefined,
  opts: { removeTypeAll?: boolean, startDate?: string, endDate?: string, dateAttribute?: string } = {},
) => {
  const { removeTypeAll = false, startDate = null, endDate = null, dateAttribute = 'created_at' } = opts;
  // 01. handle api filters in options
  // elementId, elementWithTargetTypes, fromId, toId, fromTypes and toTypes should be handle in options, not in filters
  // relationship_type should be put in options BUT should be kept in filters because this key can have all modes and operators
  let filtersContent = inputFilters?.filters ?? [];
  const dataSelectionElementId = R.head(filtersContent.filter((n) => n.key === 'elementId'))?.values || null;
  const dataSelectionElementWithTargetTypes = R.head(filtersContent.filter((n) => n.key === 'elementWithTargetTypes'))?.values || null;
  const dataSelectionRelationshipType = R.head(filtersContent.filter((o) => o.key === 'relationship_type'))?.values || null;
  const dataSelectionFromId = R.head(filtersContent.filter((o) => o.key === 'fromId'))?.values || null;
  const dataSelectionToId = R.head(filtersContent.filter((o) => o.key === 'toId'))?.values || null;
  const dataSelectionFromTypes = R.head(filtersContent.filter((o) => o.key === 'fromTypes'))?.values
    || null;
  const dataSelectionToTypes = R.head(filtersContent.filter((o) => o.key === 'toTypes'))?.values || null;
  filtersContent = filtersContent.filter(
    (o) => ![
      'elementId',
      'elementWithTargetTypes',
      'fromId',
      'toId',
      'fromTypes',
      'toTypes',
    ].includes(o.key),
  );
  let filters = inputFilters ? { ...inputFilters, filters: filtersContent } : undefined;
  // 02. remove 'all' in filter with key=entity_type
  if (removeTypeAll) filters = removeEntityTypeAllFromFilterGroup(filters);
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
      filterGroups: filters ? [filters] : [],
    };
  }
  return {
    filters,
    dataSelectionElementId,
    dataSelectionElementWithTargetTypes,
    dataSelectionRelationshipType,
    dataSelectionFromId,
    dataSelectionFromTypes,
    dataSelectionToId,
    dataSelectionToTypes,
  };
};

// return the i18n label corresponding to a value
export const filterValue = (filterKey: string, value?: string | null) => {
  const { t, nsd } = useFormatter();
  if (
    value
    && (booleanFilters.includes(filterKey) || inlineFilters.includes(filterKey))
  ) {
    // TODO: improvement: boolean filters based on schema definition (not an enum)
    return t(value);
  }
  if (filterKey === 'x_opencti_negative') {
    return t(value === 'true' ? 'False positive' : 'True positive');
  }
  if (value && entityTypesFilters.includes(filterKey)) {
    return value === 'all'
      ? t('entity_All')
      : t(
        value.toString()[0] === value.toString()[0].toUpperCase()
          ? `entity_${value.toString()}`
          : `relationship_${value.toString()}`,
      );
  }
  if (dateFilters.includes(filterKey)) {
    // TODO: improvement: date filters based on schema definition (not an enum)
    return nsd(value);
  }
  return value;
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
    filters: filterGroup?.filters?.filter((f) => f.values.length > 0)
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
  filterGroup: GqlFilterGroup | string | null,
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
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters?.mode ?? 'and',
    filters: (filters?.filters ?? []).concat([
      {
        id: uuid(),
        key,
        values: Array.isArray(value) ? value : [value],
        operator,
        mode,
      },
    ]),
    filterGroups: filters?.filterGroups ?? [],
  };
};

// forcefully remove a filter into a filterGroup, no check done
export const removeFilter = (
  filters: FilterGroup | undefined,
  key: string | string[],
) => {
  if (!filters) {
    return undefined;
  }
  const newFilters = {
    ...filters,
    filters: Array.isArray(key)
      ? filters.filters.filter((f) => !key.includes(f.key))
      : filters.filters.filter((f) => f.key !== key),
  };

  return isFilterGroupNotEmpty(newFilters) ? newFilters : undefined;
};

/**
 * remove from filter all keys not listed in availableFilterKeys
 * if filter ends up empty, return undefined
 * Note: This function is not recursive, it only filters the first level filters
 */
export const cleanFilters = (
  filters: FilterGroup | undefined,
  availableFilterKeys: string[],
) => {
  if (!filters) {
    return undefined;
  }
  const newFilters = {
    ...filters,
    filters: filters.filters.filter((f) => availableFilterKeys.includes(f.key)),
  };

  return isFilterGroupNotEmpty(newFilters) ? newFilters : undefined;
};

//----------------------------------------------------------------------------------------------------------------------

// add a filter (k, id, op) in a filterGroup smartly, for usage in forms
// note that we're only dealing with one-level filterGroup (no nested), so we just update the 1st level filters list
export const constructHandleAddFilter = (
  filters: FilterGroup | undefined | null,
  k: string,
  id: string | null,
  op = 'eq',
) => {
  // if the filter key is already used, update it
  if (filters && findFilterFromKey(filters.filters, k, op)) {
    const filter = findFilterFromKey(filters.filters, k, op);
    let newValues: string[] = [];
    if (id !== null) {
      newValues = isUniqFilter(k)
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
export const constructHandleRemoveFilter = (
  filters: FilterGroup | undefined | null,
  k: string,
  op = 'eq',
) => {
  if (filters) {
    const newBaseFilters = {
      ...filters,
      filters: filters.filters.filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
    };
    return isFilterGroupNotEmpty(newBaseFilters) ? newBaseFilters : undefined;
  }
  return undefined;
};

// switch the mode inside a specific filter
export const filtersAfterSwitchLocalMode = (
  filters: FilterGroup | undefined | null,
  localFilter: Filter,
) => {
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
export const getDefaultOperatorFilter = (filterKey: string) => {
  if (EqFilters.includes(filterKey)) {
    return 'eq';
  }
  if (dateFilters.includes(filterKey)) {
    return 'gte';
  }
  if (integerFilters.includes(filterKey)) {
    return 'gt';
  }
  if (booleanFilters.includes(filterKey)) {
    return 'eq';
  }
  if (textFilters.includes(filterKey)) {
    return 'starts_with';
  }
  return 'eq';
};

export const getDefaultFilterObject = (key: string): Filter => {
  return {
    ...defaultFilterObject,
    id: uuid(),
    key,
    operator: getDefaultOperatorFilter(key),
  };
};

export const getAvailableOperatorForFilter = (filterKey: string): string[] => {
  if (filtersUsedAsApiParameters.includes(filterKey)) {
    return ['eq'];
  }
  if (dateFilters.includes(filterKey)) {
    return ['gt', 'gte', 'lt', 'lte'];
  }
  if (integerFilters.includes(filterKey)) {
    return ['gt', 'gte', 'lt', 'lte'];
  }
  if (booleanFilters.includes(filterKey)) {
    return ['eq', 'not_eq'];
  }
  if (textFilters.includes(filterKey)) {
    return ['eq', 'not_eq', 'nil', 'not_nil', 'contains', 'not_contains',
      'starts_with', 'not_starts_with', 'ends_with', 'not_ends_with'];
  }
  return ['eq', 'not_eq', 'nil', 'not_nil'];
};

export const removeIdFromFilterGroupObject = (
  filters?: FilterGroup | null,
): FilterGroup | undefined => {
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters.mode,
    filters: filters.filters
      .filter((f) => ['nil', 'not_nil'].includes(f.operator) || f.values.length > 0)
      .map((f) => {
        const newFilter = { ...f };
        delete newFilter.id;
        return newFilter;
      }),
    filterGroups: filters.filterGroups.map((group) => removeIdFromFilterGroupObject(group)) as FilterGroup[],
  };
};

export const isStixObjectTypes = [
  'elementId',
  'fromId',
  'toId',
  'objects',
  'targets',
  'indicates',
  'contextEntityId',
];
