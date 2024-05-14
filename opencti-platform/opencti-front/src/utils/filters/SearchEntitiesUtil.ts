import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import { isStixObjectTypes } from './filtersUtils';

// eslint-disable-next-line import/prefer-default-export
export const getOptionsFromEntities = (
  entities: Record<string, OptionValue[]>,
  searchScope: Record<string, string[]>,
  filterKey: string,
): OptionValue[] => {
  let filteredOptions: OptionValue[] = [];
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
  return filteredOptions.map((f) => {
    if (f.group) {
      return f;
    } if (f.parentTypes) {
      // In case of entity we group by type
      return { ...f, group: f.type };
    }
    return f;
  })
    .sort((a, b) => {
    // In case value is null, for "no label" case we want it at the top of the list
      if (!b.value) {
        return 1;
      }
      if (a.group && b.group && a.group !== b.group) {
        return a.group.localeCompare(b.group);
      }
      return a.label.localeCompare(b.label);
    });
};
