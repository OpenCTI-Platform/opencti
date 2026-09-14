import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { Dispatch, SetStateAction, SyntheticEvent, useState } from 'react';
import { Filter } from '../../../utils/filters/filtersHelpers-types';
import { FilterSearchContext } from '../../../utils/filters/filtersUtils';
import useSearchEntities from '../../../utils/filters/useSearchEntities';

export interface FilterEditorInputValue {
  key: string;
  values: string[];
  operator?: string;
}

export interface FilterEditorState {
  inputValues: FilterEditorInputValue[];
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
  autocompleteInputValues: Record<string, string>;
  setAutocompleteInputValues: Dispatch<SetStateAction<Record<string, string>>>;
  cacheEntities: Record<string, FilterOptionValue[]>;
  setCacheEntities: Dispatch<Record<string, FilterOptionValue[]>>;
  searchScope: Record<string, string[]>;
  setSearchScope: Dispatch<SetStateAction<Record<string, string[]>>>;
  entities: Record<string, FilterOptionValue[]>;
  searchEntities: (
    filterKey: string,
    cacheEntities: Record<string, FilterOptionValue[]>,
    setCacheEntities: Dispatch<Record<string, FilterOptionValue[]>>,
    event: SyntheticEvent,
    isSubKey?: boolean,
  ) => Record<string, FilterOptionValue[]>;
}

interface UseFilterEditorStateArgs {
  filter?: Filter;
  entityTypes?: string[];
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
}

/**
 * Holds all the local (non-filter) state needed to edit one filter: the entity search cache,
 * the search scopes and the transient input values.
 *
 * Lives in its own leaf module (no component import) so that every editing component
 * — the chip popover, the nested-group row, the composite editors — can share the exact
 * same behaviour without creating an import cycle between them.
 */
const useFilterEditorState = ({
  filter,
  entityTypes,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
}: UseFilterEditorStateArgs): FilterEditorState => {
  const [autocompleteInputValues, setAutocompleteInputValues] = useState<Record<string, string>>({});
  const [inputValues, setInputValues] = useState<FilterEditorInputValue[]>(filter ? [filter as FilterEditorInputValue] : []);
  const [cacheEntities, setCacheEntities] = useState<Record<string, FilterOptionValue[]>>({});
  const [searchScope, setSearchScope] = useState<Record<string, string[]>>(
    availableRelationFilterTypes || {
      targets: [
        'Region',
        'Country',
        'Administrative-Area',
        'City',
        'Position',
        'Sector',
        'Organization',
        'Individual',
        'System',
        'Event',
        'Vulnerability',
      ],
    },
  );

  const [entities, searchEntities] = useSearchEntities({
    availableEntityTypes,
    availableRelationshipTypes,
    setInputValues,
    searchContext: { ...searchContext, entityTypes: [...(searchContext?.entityTypes ?? []), ...(entityTypes ?? [])] },
    searchScope,
  }) as [Record<string, FilterOptionValue[]>, FilterEditorState['searchEntities']];

  return {
    inputValues,
    setInputValues,
    autocompleteInputValues,
    setAutocompleteInputValues,
    cacheEntities,
    setCacheEntities,
    searchScope,
    setSearchScope,
    entities,
    searchEntities,
  };
};

export default useFilterEditorState;
