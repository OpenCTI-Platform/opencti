import type { Filter, FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

// The backend sends a blocked transition's conditions as a JSON filter group
// whose keys may be arrays (e.g. `key: ['objectAssignee']`). The front end
// expects one string key per filter.

const keyOf = (filter: Filter): string => {
  const key = filter.key as string | string[];
  return Array.isArray(key) ? key[0] : key;
};

const withStringKeys = (group: FilterGroup): FilterGroup => ({
  mode: group.mode,
  filters: (group.filters ?? []).map((f) => ({ ...f, key: keyOf(f) })),
  filterGroups: (group.filterGroups ?? []).map(withStringKeys),
});

export const parseBlockingConditions = (blockingConditions: string | null | undefined): FilterGroup | null => {
  if (!blockingConditions) return null;
  try {
    const parsed = JSON.parse(blockingConditions) as FilterGroup | null;
    return parsed && typeof parsed === 'object' ? withStringKeys(parsed) : null;
  } catch {
    return null;
  }
};

export const blockingConditionKeys = (filters: FilterGroup | null): string[] => {
  if (!filters) return [];
  const keys: string[] = [];
  const visit = (group: FilterGroup) => {
    (group.filters ?? []).forEach((f) => {
      const key = keyOf(f);
      if (key && !keys.includes(key)) keys.push(key);
    });
    (group.filterGroups ?? []).forEach(visit);
  };
  visit(filters);
  return keys;
};
