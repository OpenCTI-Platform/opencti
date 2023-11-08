import * as R from 'ramda';
import { head, last, toPairs } from 'ramda';
import { useFormatter } from '../../components/i18n';

export const FiltersVariant = {
  list: 'list',
  dialog: 'dialog',
};

export type FilterGroup = {
  mode: string;
  filters: Filter[];
  filterGroups: FilterGroup[];
};

export type Filter = {
  key: string;
  values: string[];
  operator: string;
  mode: string;
};

export const initialFilterGroup = {
  mode: 'and',
  filters: [],
  filterGroups: [],
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
];
export const inlineFilters = [
  'is_read',
  'trigger_type',
  'instance_trigger',
];
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
  'x_opencti_base_score_gt',
  'x_opencti_base_score_lte',
  'x_opencti_base_score_lte',
  'confidence_gt',
  'confidence_lte',
  'likelihood_gt',
  'likelihood_lte',
  'x_opencti_negative',
  'x_opencti_score_gt',
  'x_opencti_score_lte',
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

export const filtersWithEntityType = (filters: FilterGroup | undefined, type: string | string[]) => {
  const entityTypeFilter = {
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

export const isFilterGroupNotEmpty = (filterGroup: FilterGroup | undefined) => {
  return filterGroup && (filterGroup.filters.length > 0 || filterGroup.filterGroups.length > 0);
};

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

export const addFilter = (filters: FilterGroup, key: string, value: string | string[], operator = 'eq', mode = 'or') => {
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
export const removeFilter = (filters: FilterGroup, key: string | string[]) => {
  return filters ? {
    ...filters,
    filters: Array.isArray(key)
      ? filters.filters.filter((f) => !key.includes(f.key))
      : filters.filters.filter((f) => f.key !== key),
  } : initialFilterGroup;
};

export const cleanFilters = (filters: FilterGroup | undefined, availableFilterKeys: string[]) => {
  if (!filters) {
    return initialFilterGroup;
  }
  return {
    ...filters,
    filters: filters.filters.filter((f) => availableFilterKeys.includes(f.key)),
  };
};

export const constructHandleAddFilter = (filters: FilterGroup | undefined, k: string, id: string | null, op = 'eq') => {
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
    const newBaseFilters = {
      ...filters,
      filters: [
        ...filters.filters.filter((f) => f.key !== k || f.operator !== op), // remove filter with k as key
        newFilterElement, // add new filter
      ],
    };
    return newBaseFilters;
  }
  const newFilterElement = {
    key: k,
    values: id !== null ? [id] : [],
    operator: op ?? 'eq',
    mode: 'or',
  };
  const newBaseFilters = filters ? {
    ...filters,
    filters: [...filters.filters, newFilterElement], // add new filter
  } : {
    mode: 'and',
    filterGroups: [],
    filters: [newFilterElement],
  };
  return newBaseFilters;
};

export const constructHandleRemoveFilter = (filters: FilterGroup | undefined, k: string, op = 'eq') => {
  if (filters) {
    const newBaseFilters = {
      ...filters,
      filters: filters.filters
        .filter((f) => f.key !== k || f.operator !== op), // remove filter with key=k and operator=op
    };
    return newBaseFilters;
  }
  return undefined;
};

export const filtersAfterSwitchLocalMode = (filters: FilterGroup, localFilter: Filter) => {
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

// convert filters that are in a format before OpenCTI 5.11 (included) to the new format introduced in 5.12
export const convertOldFilters = (filters: string) => {
  const filterKeysConvertor = new Map([
    ['labelledBy', 'objectLabel'],
    ['markedBy', 'objectMarking'],
    ['objectContains', 'objects'],
    ['killChainPhase', 'killChainPhases'],
    ['assigneeTo', 'objectAssignee'],
    ['participant', 'objectParticipant'],
    ['creator', 'creator_id'],
    ['hasExternalReference', 'externalReferences'],
    ['hashes_MD5', 'hashes.MD5'],
    ['hashes_SHA1', 'hashes.SHA-1'],
    ['hashes_SHA256', 'hashes.SHA-256'],
    ['hashes_SHA512', 'hashes.SHA-512'],
  ]);
  if (JSON.parse(filters).mode) { // filters already in new format are not converted again (protection)
    return filters;
  }
  const newFiltersContent = toPairs(JSON.parse(filters))
    .map((pair) => {
      let key = head(pair);
      let operator = 'eq';
      let mode = 'or';
      if (key.endsWith('start_date') || key.endsWith('_gt')) {
        key = key.replace('_start_date', '').replace('_gt', '');
        operator = 'gt';
      } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
        key = key.replace('_end_date', '').replace('_lt', '');
        operator = 'lt';
      } else if (key.endsWith('_lte')) {
        key = key.replace('_lte', '');
        operator = 'lte';
      } else if (key.endsWith('_not_eq')) {
        key = key.replace('_not_eq', '');
        operator = 'not_eq';
        mode = 'and';
      }
      const gotKey = filterKeysConvertor.get(key);
      if (gotKey) {
        key = gotKey;
      }
      const values = last(pair);
      const valIds = values.map((v: { id: string, value: string }) => v.id);
      return { key, values: valIds, operator, mode };
    });
  return {
    mode: 'and',
    filters: newFiltersContent,
    filterGroups: [],
  };
};
