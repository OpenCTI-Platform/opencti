import { v4 as uuid } from 'uuid';
import { Filter, FilterGroup, FilterValue } from './filtersHelpers-types';
import { DEFAULT_WITHIN_FILTER_VALUES } from './filtersUtils';

type FiltersLocalStorageUtilProps<U> = {
  filters: FilterGroup;
} & U;

/**
 * Applies `updateFn` to every filter of the whole tree (root filters + filters of every nested
 * group, at any depth).
 * Filter ids are uuids and unique tree-wide, so the filter-level utils never need a groupId:
 * they simply recurse until they find the filter with the matching id.
 * Non-mutating: a new tree is built, the input (possibly frozen) is never touched.
 */
const updateFilters = (filters: FilterGroup, updateFn: (filter: Filter) => Filter): FilterGroup => {
  return {
    ...filters,
    filters: (filters.filters ?? []).map(updateFn),
    filterGroups: (filters.filterGroups ?? []).map((group) => updateFilters(group, updateFn)),
  } as FilterGroup;
};

/**
 * Non-mutating walker returning a new tree where the group identified by `groupId` has been
 * replaced by `updater(group)`. When `groupId` is undefined, the ROOT group is targeted.
 * An unknown groupId is a no-op (the very same object is returned).
 */
export const updateGroupById = (
  filterGroup: FilterGroup,
  groupId: string | undefined,
  updater: (group: FilterGroup) => FilterGroup,
): FilterGroup => {
  if (groupId === undefined || filterGroup.id === groupId) {
    return updater(filterGroup);
  }
  const subGroups = filterGroup.filterGroups ?? [];
  const newSubGroups = subGroups.map((group) => updateGroupById(group, groupId, updater));
  if (newSubGroups.every((group, index) => group === subGroups[index])) {
    return filterGroup;
  }
  return {
    ...filterGroup,
    filterGroups: newSubGroups,
  };
};

export const handleAddFilterWithEmptyValueUtil = ({ filters, filter, groupId }: FiltersLocalStorageUtilProps<{
  filter: Filter;
  groupId?: string;
}>): FilterGroup => {
  return updateGroupById(filters, groupId, (group) => ({
    ...group,
    filters: [
      ...(group.filters ?? []),
      filter,
    ],
  }));
};

/**
 * Appends a new empty sub-group inside the designated parent group (the root group when
 * `parentGroupId` is omitted).
 */
export const addFilterGroupUtil = ({ filters, parentGroupId }: FiltersLocalStorageUtilProps<{
  parentGroupId?: string;
}>): FilterGroup => {
  const newGroup: FilterGroup = {
    id: uuid(),
    mode: 'and',
    filters: [],
    filterGroups: [],
  };
  return updateGroupById(filters, parentGroupId, (group) => ({
    ...group,
    filterGroups: [
      ...(group.filterGroups ?? []),
      newGroup,
    ],
  }));
};

/**
 * Removes the group identified by `groupId` and everything under it.
 * The ROOT group is never removable.
 */
export const removeFilterGroupUtil = ({ filters, groupId }: FiltersLocalStorageUtilProps<{
  groupId: string;
}>): FilterGroup => {
  if (filters.id === groupId) { // the root group can't be removed
    return filters;
  }
  const subGroups = filters.filterGroups ?? [];
  const keptSubGroups = subGroups
    .filter((group) => group.id !== groupId)
    .map((group) => removeFilterGroupUtil({ filters: group, groupId }));
  if (keptSubGroups.length === subGroups.length && keptSubGroups.every((group, index) => group === subGroups[index])) {
    return filters;
  }
  return {
    ...filters,
    filterGroups: keptSubGroups,
  };
};

/**
 * Switches the and/or mode of the given group (the root group when `groupId` is omitted).
 */
export const handleSwitchGlobalModeUtil = ({ filters, groupId }: FiltersLocalStorageUtilProps<{
  groupId?: string;
}>): FilterGroup => {
  return updateGroupById(filters, groupId, (group) => ({
    ...group,
    mode: group.mode === 'and' ? 'or' : 'and',
  }));
};

export const handleChangeOperatorFiltersUtil = ({ filters, id, operator }: FiltersLocalStorageUtilProps<{
  id: string;
  operator: string;
}>): FilterGroup => {
  return updateFilters(filters, (f) => {
    if (f.id === id) {
      let values = [...f.values];
      if (['nil', 'not_nil'].includes(operator)) {
        values = [];
      } else if (operator === 'within' && f.operator !== 'within') {
        values = DEFAULT_WITHIN_FILTER_VALUES;
      } else if (f.operator === 'within' && operator !== 'within') {
        values = [];
      }
      return {
        ...f,
        operator,
        values,
      };
    }
    return f;
  });
};

export const handleSwitchLocalModeUtil = ({ filters, filter }: FiltersLocalStorageUtilProps<{
  filter: Filter;
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === filter.id
    ? { ...f, mode: filter.mode === 'and' ? 'or' : 'and' }
    : f));
};

export const handleAddRepresentationFilterUtil = ({ filters, id, value }: FiltersLocalStorageUtilProps<{
  id: string;
  value: string | FilterValue;
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [...f.values, value] } : f));
};

export const handleAddSingleValueFilterUtil = ({ filters, id, valueId }: FiltersLocalStorageUtilProps<{
  id: string;
  valueId?: string;
}>): FilterGroup => {
  if (valueId) {
    return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [valueId] } : f));
  }
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values: [] } : f));
};

export const handleReplaceFilterValuesUtil = ({ filters, id, values }: FiltersLocalStorageUtilProps<{
  id: string;
  values: string[] | FilterGroup[];
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id ? { ...f, values } : f));
};

export const handleRemoveRepresentationFilterUtil = ({ filters, id, value }: FiltersLocalStorageUtilProps<{
  id: string;
  value: string | FilterValue;
}>): FilterGroup => {
  return updateFilters(filters, (f) => (f.id === id
    ? {
        ...f,
        values: f.values.filter((v) => v !== value),
      }
    : f));
};

const removeFilterFromTree = (filterGroup: FilterGroup, id: string): FilterGroup => ({
  ...filterGroup,
  filters: (filterGroup.filters ?? []).filter((f) => f.id !== id),
  filterGroups: (filterGroup.filterGroups ?? []).map((group) => removeFilterFromTree(group, id)),
});

export const handleRemoveFilterUtil = ({ filters, id }: FiltersLocalStorageUtilProps<{ id: string }>): FilterGroup => {
  return removeFilterFromTree(filters, id);
};

export const handleChangeRepresentationFilterUtil = ({ filters, id, oldValue, newValue }: FiltersLocalStorageUtilProps<{
  id: string;
  oldValue: FilterValue;
  newValue: FilterValue;
}>): FilterGroup => {
  return updateFilters(
    filters,
    (f) => (f.id === id
      ? { ...f, values: f.values.filter((val) => val !== oldValue).concat([newValue]) }
      : f),
  );
};
