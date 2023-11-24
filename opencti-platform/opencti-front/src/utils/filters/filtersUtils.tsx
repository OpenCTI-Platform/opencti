import * as R from 'ramda';
import { useFormatter } from '../../components/i18n';

import type {
  FilterGroup as GqlFilterGroup,
} from './__generated__/useSearchEntitiesStixCoreObjectsContainersSearchQuery.graphql';

//----------------------------------------------------------------------------------------------------------------------

export type {
  FilterGroup as GqlFilterGroup,
} from './__generated__/useSearchEntitiesStixCoreObjectsContainersSearchQuery.graphql';

export type FilterGroup = {
  mode: string;
  filters: Filter[];
  filterGroups: FilterGroup[];
};

// TODO: import from graphql generated types
export type Filter = {
  key: string; // key is a string in front
  values: string[];
  operator: string;
  mode: string;
};

export const initialFilterGroup = {
  mode: 'and',
  filters: [],
  filterGroups: [],
};

//----------------------------------------------------------------------------------------------------------------------

export const FiltersVariant = {
  list: 'list',
  dialog: 'dialog',
};

export const onlyGroupOrganization = ['x_opencti_workflow_id'];

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
  'note_types',
  'context',
  'trigger_type',
  'instance_trigger',
  'containers',
  'objectContains',
];

export const inlineFilters = ['is_read', 'trigger_type', 'instance_trigger'];
// filters that can have 'eq' or 'not_eq' operator
export const EqFilters = [
  'objectLabel',
  'createdBy',
  'objectMarking',
  'entity_type',
  'x_opencti_workflow_id',
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
  'basedOn',
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
];

export const booleanFilters = [
  'x_opencti_detection',
  'revoked',
  'is_read',
  'x_opencti_reliability',
];

export const entityTypesFilters = [
  'entity_type',
  'entity_types',
  'fromTypes',
  'toTypes',
  'relationship_types',
  'container_type',
];

//----------------------------------------------------------------------------------------------------------------------
// utilities

export const isFilterGroupNotEmpty = (filterGroup: FilterGroup | undefined) => {
  return filterGroup && (filterGroup.filters.length > 0 || filterGroup.filterGroups.length > 0);
};

export const isUniqFilter = (key: string) => uniqFilters.includes(key) || dateFilters.includes(key);

export const findFilterFromKey = (filters: Filter[], key: string, operator?: string) => {
  for (const filter of filters) {
    if (filter.key === key) {
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

export const findFiltersFromKeys = (filters: Filter[], keys: string[], operator?: string) => {
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

export const findFilterIndexFromKey = (filters: Filter[], key: string, operator?: string) => {
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

export const filtersWithEntityType = (filters: FilterGroup | undefined, type: string | string[]): FilterGroup => {
  const entityTypeFilter : Filter = {
    key: 'entity_type',
    values: Array.isArray(type) ? type : [type],
    operator: 'eq',
    mode: 'or',
  };
  return {
    mode: filters?.mode ?? 'and',
    filterGroups: filters?.filterGroups ?? [],
    filters: filters
      ? [
        ...filters.filters,
        entityTypeFilter,
      ]
      : [entityTypeFilter],
  };
};

// return the i18n label corresponding to a value
export const filterValue = (filterKey: string, value?: string | null) => {
  const { t, nsd } = useFormatter();
  if (booleanFilters.includes(filterKey) || inlineFilters.includes(filterKey)) { // TODO: improvement: boolean filters based on schema definition (not an enum)
    return t(value);
  }
  if (filterKey === 'basedOn') {
    return value === 'EXISTS' ? t('Yes') : t('No');
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
  if (dateFilters.includes(filterKey)) { // TODO: improvement: date filters based on schema definition (not an enum)
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
const sanitizeFilterGroupKeysForBackend = (filterGroup: FilterGroup): GqlFilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => ({ ...f, key: Array.isArray(f.key) ? f.key : [f.key] })),
    filterGroups: filterGroup.filterGroups.map((fg) => sanitizeFilterGroupKeysForBackend(fg)),
  } as GqlFilterGroup;
};

// reverse operation of sanitizeFilterGroupKeysForBackend
const sanitizeFilterGroupKeysForFrontend = (filterGroup: GqlFilterGroup) : FilterGroup => {
  return {
    ...filterGroup,
    filters: filterGroup.filters.map((f) => ({ ...f, key: Array.isArray(f.key) ? f.key[0] : f.key })),
    filterGroups: filterGroup.filterGroups.map((fg) => sanitizeFilterGroupKeysForFrontend(fg)),
  } as FilterGroup;
};

/**
 * Turns a FilterGroup (frontend format, i.e. with single keys) into the backend format (key is an array)
 * and stringify it, ready to be saved in backend.
 * @param filterGroup
 */
export const serializeFilterGroupForBackend = (filterGroup?: FilterGroup | null): string => {
  if (!filterGroup) {
    return JSON.stringify(initialFilterGroup);
  }
  return JSON.stringify(sanitizeFilterGroupKeysForBackend(filterGroup));
};

/**
 * Parse a filterGroup as given by the backend (backend format, i.e. with array keys),
 * And turns it into the frontend format (single key).²
 * @param filterGroup
 */
export const deserializeFilterGroupForFrontend = (filterGroup: GqlFilterGroup | string | null): FilterGroup | null => {
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
export const serializeDashboardManifestForBackend = (manifest: AnyForDashboardManifest) : string => {
  const newWidgets: Record<string, AnyForDashboardManifest> = {};
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    newWidgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map((selection: AnyForDashboardManifest) => ({
        ...selection,
        filters: sanitizeFilterGroupKeysForBackend(selection.filters),
        dynamicFrom: sanitizeFilterGroupKeysForBackend(selection.dynamicFrom),
        dynamicTo: sanitizeFilterGroupKeysForBackend(selection.dynamicTo),
      })),
    };
  });

  return JSON.stringify({
    ...manifest,
    widgets: newWidgets,
  });
};

export const deserializeDashboardManifestForFrontend = (manifestStr: string) : AnyForDashboardManifest => {
  const manifest = JSON.parse(manifestStr);

  const newWidgets: Record<string, AnyForDashboardManifest> = {};
  const widgetIds = manifest.widgets ? Object.keys(manifest.widgets) : [];
  widgetIds.forEach((id) => {
    const widget = manifest.widgets[id];
    newWidgets[id] = {
      ...widget,
      dataSelection: widget.dataSelection.map((selection: AnyForDashboardManifest) => ({
        ...selection,
        filters: sanitizeFilterGroupKeysForFrontend(selection.filters),
        dynamicFrom: sanitizeFilterGroupKeysForFrontend(selection.dynamicFrom),
        dynamicTo: sanitizeFilterGroupKeysForFrontend(selection.dynamicTo),
      })),
    };
  });

  return {
    ...manifest,
    widgets: newWidgets,
  };
};

//----------------------------------------------------------------------------------------------------------------------

// forcefully add a filter into a filterGroup, no check done
export const addFilter = (filters: FilterGroup | undefined, key: string, value: string | string[], operator = 'eq', mode = 'or'): FilterGroup | undefined => {
  if (!filters) {
    return undefined;
  }
  return {
    mode: filters?.mode ?? 'and',
    filters: (filters?.filters ?? []).concat([
      {
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
export const removeFilter = (filters: FilterGroup | undefined, key: string | string[]) => {
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

// remove from filter all keys not listed in availableFilterKeys
// if filter ends up empty, return undefined
export const cleanFilters = (filters: FilterGroup | undefined, availableFilterKeys: string[]) => {
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
export const constructHandleAddFilter = (filters: FilterGroup | undefined | null, k: string, id: string | null, op = 'eq') => {
  // if the filter key is already used, update it
  if (filters && findFilterFromKey(filters.filters, k, op)) {
    const filter = findFilterFromKey(filters.filters, k, op);
    let newValues: string[] = [];
    if (id !== null) {
      newValues = isUniqFilter(k) ? [id] : R.uniq([...filter?.values ?? [], id]);
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
  return filters ? {
    ...filters,
    filters: [...filters.filters, newFilterElement], // add new filter
  } : {
    mode: 'and',
    filterGroups: [],
    filters: [newFilterElement],
  };
};

// remove a filter (k, id, op) in a filterGroup smartly, for usage in forms
// if the filter ends up empty, return undefined
export const constructHandleRemoveFilter = (filters: FilterGroup | undefined | null, k: string, op = 'eq') => {
  if (filters) {
    const newBaseFilters = {
      ...filters,
      filters: filters.filters
        .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
    };
    return isFilterGroupNotEmpty(newBaseFilters) ? newBaseFilters : undefined;
  }
  return undefined;
};

// switch the mode inside a specific filter
export const filtersAfterSwitchLocalMode = (filters: FilterGroup | undefined | null, localFilter: Filter) => {
  if (filters) {
    const filterIndex = findFilterIndexFromKey(filters.filters, localFilter.key, localFilter.operator);
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
