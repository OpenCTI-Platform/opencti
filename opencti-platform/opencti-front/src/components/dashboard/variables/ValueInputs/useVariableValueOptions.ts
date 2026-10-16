import { SyntheticEvent, useState } from 'react';
import type { ComboboxChangeCause } from '@filigran/design-system';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import useAuth from '../../../../utils/hooks/useAuth';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import { getOptionsFromEntities } from '../../../../utils/filters/SearchEntitiesUtil';
import { ME_FILTER_VALUE } from '../../../../utils/filters/filtersUtils';
import { VARIABLE_SEARCH_CONTEXT, VARIABLE_TYPE_SEARCH } from '../variableTypeSearch';
import type { DashboardVariableShape } from '../DashboardVariableValueInput';
import useKillChainPhaseSearch from './useKillChainPhaseSearch';
import useRestrictedEntitySearch from './useRestrictedEntitySearch';

export interface VariableValueOptions {
  options: FilterOptionValue[];
  // Runs the search of a text: on each keystroke (`type`), and from an empty text when the field is focused.
  search: (event: SyntheticEvent, text: string, cause?: ComboboxChangeCause) => void;
  // Listing the phases of a kill chain needs the knowledge access: without it no value can be chosen, and the input
  // says why instead of showing an empty list.
  hasListingError: boolean;
}

/**
 * Server side search of the candidate values of an entity pool variable (entity, label, marking, user, group, status,
 * kill chain phase) or of an entity type, through the same search as the filters. A kill chain phase is searched among the
 * phases of the kill chain of the variable only, on the server (see useKillChainPhaseSearch). An entity variable
 * restricted by filters is searched among the entities that match its rule (see useRestrictedEntitySearch).
 * Shared by the input of one value and the input of the values of a selection.
 */
const useVariableValueOptions = (variable: DashboardVariableShape): VariableValueOptions => {
  const searchKey = VARIABLE_TYPE_SEARCH[variable.type] ?? 'id';
  const searchScope = variable.type === 'entity' ? { [searchKey]: variable.entityTypes ?? [] } : {};
  // The shared search drops External-Reference from the scope, which it can only search for a regardingOf filter:
  // left with no type, it would read the scope as "any entity". Such a variable searches nothing.
  const entityTypes = variable.type === 'entity' ? variable.entityTypes ?? [] : [];
  const isSearchable = entityTypes.length === 0 || entityTypes.some((type) => type !== 'External-Reference');
  const [cacheEntities, setCacheEntities] = useState<Record<string, FilterOptionValue[]>>({});
  const [entities, searchEntities] = useSearchEntities({ searchContext: VARIABLE_SEARCH_CONTEXT, searchScope, setInputValues: () => {} });
  const isKillChainPhase = variable.type === 'killChainPhase';
  const killChainPhases = useKillChainPhaseSearch(variable.killChainName);
  const isRestrictedByFilters = variable.type === 'entity' && variable.restriction.mode === 'filters';
  // The restricted search runs on Stix-Core-Objects, which drop any other type and fall back to every core object
  // when none is left: the meta object types (Label, Marking-Definition, External-Reference...) are left out of its
  // scope, and a variable of meta object types only searches nothing.
  const { schema } = useAuth();
  const metaObjectTypes = (schema.smos ?? []).map(({ id }) => id).concat('External-Reference');
  const restrictedTypes = entityTypes.filter((entityType) => !metaObjectTypes.includes(entityType));
  const restrictedEntities = useRestrictedEntitySearch(
    restrictedTypes,
    isRestrictedByFilters && variable.restriction.mode === 'filters' ? variable.restriction.filters : undefined,
  );

  if (isRestrictedByFilters) {
    // Searched with the typed text. Picking or clearing also writes the text (the label of the pick), which is no
    // search: the list goes back to every entity of the rule.
    return {
      options: restrictedEntities.options,
      search: (_event, text, cause = 'type') => {
        if (restrictedTypes.length > 0) restrictedEntities.search(cause === 'type' ? text : '');
      },
      hasListingError: false,
    };
  }
  const options = isKillChainPhase
    ? killChainPhases.options
    : (isSearchable ? getOptionsFromEntities(entities, searchScope, searchKey) : [])
        // A variable holds an id: neither the "No label" option nor the dynamic @me user can be a value.
        .filter((option) => option.value !== null && option.value !== ME_FILTER_VALUE);

  // The kill chain phases are searched with the typed text only, and from an empty text when the field is focused.
  // Picking or clearing also writes the text (the label of the pick): the list then goes back to the whole kill chain.
  const search = (event: SyntheticEvent, text: string, cause: ComboboxChangeCause = 'type') => {
    if (isKillChainPhase) {
      if (cause === 'type') killChainPhases.search(text);
      else killChainPhases.reset();
    } else if (isSearchable) searchEntities(searchKey, cacheEntities, setCacheEntities, event);
  };

  return { options, search, hasListingError: isKillChainPhase && killChainPhases.error };
};

export default useVariableValueOptions;
