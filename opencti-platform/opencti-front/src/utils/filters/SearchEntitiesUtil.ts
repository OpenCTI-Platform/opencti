import { Dispatch, SyntheticEvent } from 'react';
import { OptionValue } from '@components/common/lists/FilterAutocomplete';
import useSearchEntities, { SearchEntitiesProps } from './useSearchEntities';

let searchEntitiesScope: SearchEntitiesProps | undefined;

export const setSearchEntitiesScope = (searchEntities: SearchEntitiesProps) => {
  searchEntitiesScope = searchEntities;
};
export const getSearchEntitiesScope = (): SearchEntitiesProps | undefined => {
  return searchEntitiesScope;
};

export const getOptionsFromEntities = (filterKey: string) => {
  let options: OptionValue[] = [];
  if (!searchEntitiesScope) {
    return [];
  }
  const [entities, _] = useSearchEntities(searchEntitiesScope) as [
    Record<string, OptionValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<string, { label: string; value: string; type: string }[]>,
      setCacheEntities: Dispatch<Record<string, { label: string; value: string; type: string }[]>>,
      event: SyntheticEvent
    ) => Record<string, OptionValue[]>,
  ];
  const { searchScope } = searchEntitiesScope;
  const isStixObjectTypes = [
    'elementId',
    'fromId',
    'toId',
    'objects',
    'targets',
    'elementId',
    'indicates',
  ].includes(filterKey);
  if (isStixObjectTypes) {
    if (searchScope[filterKey] && searchScope[filterKey].length > 0) {
      options = (entities[filterKey] || [])
        .filter((n) => searchScope[filterKey].some((s) => (n.parentTypes ?? []).concat(n.type).includes(s)))
        .sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
    } else {
      options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
    }
  } else if (entities[filterKey]) {
    options = entities[filterKey];
  }

  return options;
};

export const getUseSearch = () => {
  if (!searchEntitiesScope) {
    return [];
  }
  return useSearchEntities(searchEntitiesScope) as [
    Record<string, OptionValue[]>,
    (
      filterKey: string,
      cacheEntities: Record<string, { label: string; value: string; type: string }[]>,
      setCacheEntities: Dispatch<Record<string, { label: string; value: string; type: string }[]>>,
      event: SyntheticEvent
    ) => Record<string, OptionValue[]>,
  ];
};

export const getOptions = (filterKey: string, entities: Record<string, OptionValue[]>) => {
  let options: OptionValue[] = [];
  const isStixObjectTypes = [
    'elementId',
    'fromId',
    'toId',
    'objects',
    'targets',
    'elementId',
    'indicates',
  ].includes(filterKey);

  if (isStixObjectTypes) {
    options = (entities[filterKey] || []).sort((a, b) => (b.type ? -b.type.localeCompare(a.type) : 0));
  } else if (entities[filterKey]) {
    options = entities[filterKey];
  }
  return options;
};
