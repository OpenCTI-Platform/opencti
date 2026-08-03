import { v4 as uuid } from 'uuid';
import { Filter, FilterGroup } from './filtersHelpers-types';

// A path addresses a nested group by the successive indices in `filterGroups`.
// The root group is addressed by an empty path [].
export type FilterGroupPath = number[];

/**
 * Ensures every filter has an id and every nested group has the expected shape.
 * Filters need a stable id to be editable through the shared filter helpers.
 */
export const ensureFilterGroupIds = (group: FilterGroup): FilterGroup => ({
  mode: group.mode ?? 'and',
  filters: (group.filters ?? []).map((f) => ({ ...f, id: f.id ?? uuid() })),
  filterGroups: (group.filterGroups ?? []).map(ensureFilterGroupIds),
});

/**
 * Recursively updates a filter identified by its id, wherever it is in the tree.
 */
export const updateFilterInTree = (
  group: FilterGroup,
  id: string,
  updateFn: (filter: Filter) => Filter,
): FilterGroup => ({
  ...group,
  filters: group.filters.map((f) => (f.id === id ? updateFn(f) : f)),
  filterGroups: group.filterGroups.map((g) => updateFilterInTree(g, id, updateFn)),
});

/**
 * Recursively removes a filter identified by its id, wherever it is in the tree.
 */
export const removeFilterInTree = (group: FilterGroup, id: string): FilterGroup => ({
  ...group,
  filters: group.filters.filter((f) => f.id !== id),
  filterGroups: group.filterGroups.map((g) => removeFilterInTree(g, id)),
});

/**
 * Flattens every leaf filter of the tree into a single array.
 * Used so the shared FilterChipPopover can find a filter by its id.
 */
export const flattenFilters = (group: FilterGroup): Filter[] => [
  ...group.filters,
  ...group.filterGroups.flatMap(flattenFilters),
];

/**
 * Applies an update function to the group located at the given path.
 */
export const updateGroupAtPath = (
  group: FilterGroup,
  path: FilterGroupPath,
  updateFn: (g: FilterGroup) => FilterGroup,
): FilterGroup => {
  if (path.length === 0) {
    return updateFn(group);
  }
  const [index, ...rest] = path;
  return {
    ...group,
    filterGroups: group.filterGroups.map((g, i) => (i === index ? updateGroupAtPath(g, rest, updateFn) : g)),
  };
};

export const addFilterAtPath = (
  group: FilterGroup,
  path: FilterGroupPath,
  filter: Filter,
): FilterGroup => updateGroupAtPath(group, path, (g) => ({
  ...g,
  filters: [...g.filters, filter],
}));

export const addSubGroupAtPath = (
  group: FilterGroup,
  path: FilterGroupPath,
  mode = 'or',
): FilterGroup => updateGroupAtPath(group, path, (g) => ({
  ...g,
  filterGroups: [...g.filterGroups, { mode, filters: [], filterGroups: [] }],
}));

export const removeGroupAtPath = (group: FilterGroup, path: FilterGroupPath): FilterGroup => {
  if (path.length === 0) {
    return group; // the root group cannot be removed
  }
  const parentPath = path.slice(0, -1);
  const index = path[path.length - 1];
  return updateGroupAtPath(group, parentPath, (g) => ({
    ...g,
    filterGroups: g.filterGroups.filter((_, i) => i !== index),
  }));
};

export const setGroupModeAtPath = (
  group: FilterGroup,
  path: FilterGroupPath,
  mode: string,
): FilterGroup => updateGroupAtPath(group, path, (g) => ({ ...g, mode }));
