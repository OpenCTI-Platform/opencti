import { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { Dispatch, SetStateAction, SyntheticEvent, useState } from 'react';
import { Filter, FilterEditorInputValue } from '../../../utils/filters/filtersHelpers-types';
import { getSelectedOptions, SELF_ID, SELF_ID_VALUE, useFilterDefinition } from '../../../utils/filters/filtersUtils';
import { getOptionsFromEntities } from '../../../utils/filters/SearchEntitiesUtil';
import useSearchEntities from '../../../utils/filters/useSearchEntities';
import useAttributes from '../../../utils/hooks/useAttributes';
import { FilterDefinition } from '../../../utils/hooks/useAuth';
import { useFormatter } from '../../i18n';
import { useFilterEditorContext } from './FilterEditorContext';
import { getEditedValues } from './filterEntityValueActions';

interface UseFilterEntityOptionsArgs {
  filter?: Filter;
  filterKey: string;
  subKey?: string;
  setInputValues: Dispatch<SetStateAction<FilterEditorInputValue[]>>;
}

const DEFAULT_TARGETS_SEARCH_SCOPE = [
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
];

const isIdFilterDefinition = (
  fDefinition?: FilterDefinition,
  currentSubKey?: string,
) => {
  if (!fDefinition) return false;
  return fDefinition.type === 'id'
    || (fDefinition.filterKey === 'regardingOf' && currentSubKey === 'id');
};

/**
 * Server-side search behind the entity autocomplete: owns the search scope, the entity
 * cache, the typed input and the assembly of the option list (already selected values
 * first, then the search results, plus the contextual `SELF_ID` option).
 *
 * Extracted from the component so the option list can be tested and evolved without
 * touching the MUI Autocomplete kept for gap #155.
 */
const useFilterEntityOptions = ({
  filter,
  filterKey,
  subKey,
  setInputValues,
}: UseFilterEntityOptionsArgs) => {
  const { t_i18n } = useFormatter();
  const {
    filtersRepresentativesMap,
    entityTypes,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    searchContext,
    host,
  } = useFilterEditorContext();
  const { typesWithFintelTemplates } = useAttributes();
  const [autocompleteInputValues, setAutocompleteInputValues] = useState<Record<string, string>>({});
  const [cacheEntities, setCacheEntities] = useState<Record<string, FilterOptionValue[]>>({});
  const [searchScope, setSearchScope] = useState<Record<string, string[]>>(
    availableRelationFilterTypes || { targets: DEFAULT_TARGETS_SEARCH_SCOPE },
  );

  const [entities, searchEntities] = useSearchEntities({
    availableEntityTypes,
    availableRelationshipTypes,
    setInputValues,
    searchContext: { ...searchContext, entityTypes: [...(searchContext?.entityTypes ?? []), ...(entityTypes ?? [])] },
    searchScope,
  });

  // A subfilter searches under its own key (e.g. 'relationship_type'), the filter under its own.
  const searchKey = subKey ?? filterKey;
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const optionsValues = getEditedValues(filter, subKey);

  const completedTypesWithFintelTemplates = typesWithFintelTemplates.concat(['Container', 'Stix-Domain-Object', 'Stix-Core-Object']);
  const shouldAddSelfIdInFintelTemplates = host?.kind === 'fintelTemplate'
    && (filterDefinition?.elementsForFilterValuesSearch ?? []).every((type) => completedTypesWithFintelTemplates.includes(type));
  const shouldAddSelfIdInCustomViews = host?.kind === 'custom-view';
  const shouldAddSelfId = isIdFilterDefinition(filterDefinition, subKey)
    && (shouldAddSelfIdInFintelTemplates || shouldAddSelfIdInCustomViews);

  const entitiesOptionsFromSearch = getOptionsFromEntities(entities, searchScope, searchKey);
  const allOptions = shouldAddSelfId
    ? [
        {
          value: SELF_ID,
          label: SELF_ID_VALUE,
          group: 'Instance',
          parentTypes: [],
          color: 'primary',
          type: 'Instance',
        },
        ...entitiesOptionsFromSearch,
      ]
    : entitiesOptionsFromSearch;

  const selectedOptions: FilterOptionValue[] = getSelectedOptions(allOptions, optionsValues, filtersRepresentativesMap, t_i18n);
  const options = [...selectedOptions, ...allOptions.filter((option) => !optionsValues.includes(option.value))];

  const triggerSearch = (event: SyntheticEvent) => {
    searchEntities(searchKey, cacheEntities, setCacheEntities, event, !!subKey);
  };

  const setInputValue = (value: string) => {
    setAutocompleteInputValues((prev) => ({ ...prev, [searchKey]: value }));
  };

  return {
    searchKey,
    options,
    selectedOptions,
    inputValue: autocompleteInputValues[searchKey] || '',
    setInputValue,
    triggerSearch,
    searchScope,
    setSearchScope,
  };
};

export default useFilterEntityOptions;
