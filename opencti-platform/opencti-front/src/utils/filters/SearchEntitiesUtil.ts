import { Dispatch, SyntheticEvent } from 'react';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import useSearchEntities, { SearchEntitiesProps } from './useSearchEntities';
import { isStixObjectTypes } from './filtersUtils';

let searchEntitiesScope: SearchEntitiesProps | undefined;

export const setSearchEntitiesScope = (searchEntities: SearchEntitiesProps) => {
  searchEntitiesScope = searchEntities;
};

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
  return filteredOptions.map((f) => (f.group ? f : { ...f, group: f.type }))
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

export const getUseSearch = (searchScope?: Record<string, string[]>) => {
  if (!searchEntitiesScope) {
    return [];
  }
  const searchEntitiesParams = searchScope ? { ...searchEntitiesScope, searchScope } : searchEntitiesScope;
  return useSearchEntities(searchEntitiesParams) as [
    Record<string, OptionValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<string, { label: string; value: string; type: string }[]>,
      setCacheEntities: Dispatch<Record<string, { label: string; value: string; type: string }[]>>,
      event: SyntheticEvent
    ) => Record<string, OptionValue[]>,
  ];
};
