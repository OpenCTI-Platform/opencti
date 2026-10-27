import { SyntheticEvent, useState } from 'react';
import type { ComboboxChangeCause } from '@filigran/design-system';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import useAuth from '../../../../utils/hooks/useAuth';
import { useFormatter } from '../../../i18n';
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
  // Why the values cannot be listed, when a search failed: listing the phases of a kill chain needs the knowledge
  // access, and the entities of a rule may fail to be listed. The input says so instead of showing an empty list.
  listingError: string | undefined;
}

/**
 * Server side search of the candidate values of an entity pool variable (entity, label, marking, user, group, status,
 * kill chain phase) or of an entity type, through the same search as the filters. A kill chain phase is searched among the
 * phases of the kill chain of the variable only, on the server (see useKillChainPhaseSearch). An entity variable
 * restricted by filters is searched among the entities that match its rule (see useRestrictedEntitySearch).
 * Shared by the input of one value and the input of the values of a selection.
 */
const useVariableValueOptions = (variable: DashboardVariableShape): VariableValueOptions => {
  const { t_i18n } = useFormatter();
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
      listingError: restrictedEntities.error ? t_i18n('The entities matching the rule cannot be listed right now') : undefined,
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

  const listingError = isKillChainPhase && killChainPhases.error
    ? t_i18n('The kill chain phases cannot be listed with your access rights or right now')
    : undefined;
  return { options, search, listingError };
};

export default useVariableValueOptions;
