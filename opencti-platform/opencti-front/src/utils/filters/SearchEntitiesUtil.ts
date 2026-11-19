import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { isStixObjectTypes, ME_FILTER_VALUE } from './filtersUtils';

// "No label" and the dynamic @me user stay at the top of the list, whatever is typed
const pinnedRank = (option: FilterOptionValue) => {
  if (!option.value) return 0;
  if (option.value === ME_FILTER_VALUE) return 1;
  return 2;
};

/**
 * Options of the entities found by the search, "No label" and the dynamic @me user first.
 * When a term is typed, the options keep the order the search returned them in: the most relevant first, as the search
 * engine ranks its results by score. Options of the same group are kept together, as an autocomplete only groups
 * consecutive options, and the groups come in the order of their first option, so the group of the most relevant
 * entity comes first. When nothing is typed, there is no relevance to keep: groups then labels are alphabetical.
 */
export const getOptionsFromEntities = (
  entities: Record<string, FilterOptionValue[]>,
  searchScope: Record<string, string[]>,
  filterKey: string,
  searchTerm = '',
): FilterOptionValue[] => {
  let filteredOptions: FilterOptionValue[] = [];
  if (isStixObjectTypes.includes(filterKey)) {
    if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
      filteredOptions = (entities[filterKey] || [])
        .filter((n) => searchScope[filterKey].some((s) => (n.parentTypes ?? []).concat(n.type).includes(s)));
    } else {
      filteredOptions = (entities[filterKey] || []);
    }
  } else if (entities[filterKey]) {
    filteredOptions = entities[filterKey];
  }
  // In case of entity we group by type
  const options = filteredOptions.map((f) => (!f.group && f.parentTypes ? { ...f, group: f.type } : f));
  if (!searchTerm.trim()) {
    return options.sort((a, b) => pinnedRank(a) - pinnedRank(b)
      || (a.group ?? '').localeCompare(b.group ?? '')
      || (a.label ?? '').localeCompare(b.label ?? ''));
  }
  const groupOrder = new Map<string, number>();
  options.forEach(({ group }) => {
    if (!groupOrder.has(group ?? '')) groupOrder.set(group ?? '', groupOrder.size);
  });
  // The sort is stable: within a group, the options keep the order of the search
  return options.sort((a, b) => pinnedRank(a) - pinnedRank(b)
    || (groupOrder.get(a.group ?? '') ?? 0) - (groupOrder.get(b.group ?? '') ?? 0));
};
