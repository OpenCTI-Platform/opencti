import { SyntheticEvent, useState } from 'react';
import {
  Combobox,
  type ComboboxChangeCause,
  ComboboxClear,
  ComboboxContent,
  ComboboxControls,
  ComboboxField,
  ComboboxHelperText,
  ComboboxInput,
  ComboboxLabel,
  ComboboxTrigger,
} from '@filigran/design-system';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { useFormatter } from '../../../i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import { getOptionsFromEntities } from '../../../../utils/filters/SearchEntitiesUtil';
import { ME_FILTER_VALUE } from '../../../../utils/filters/filtersUtils';
import useVariableValueLabels from '../useVariableValueLabels';
import { VARIABLE_SEARCH_CONTEXT, VARIABLE_TYPE_SEARCH } from '../variableTypeSearch';
import type { ValueInputProps } from '../DashboardVariableValueInput';
import useKillChainPhaseSearch from './useKillChainPhaseSearch';

/**
 * Server side search of the value of an entity pool variable (entity, label, marking, user, group, status,
 * kill chain phase) or of an entity type, through the same search as the filters. A kill chain phase is searched among the
 * phases of the kill chain of the variable only, on the server (see useKillChainPhaseSearch).
 */
const SearchValueInput = ({ variable, value, onChange, disabled, label, commitOn }: ValueInputProps) => {
  const { t_i18n } = useFormatter();
  const searchKey = VARIABLE_TYPE_SEARCH[variable.type] ?? 'id';
  const searchScope = variable.type === 'entity' ? { [searchKey]: variable.entityTypes ?? [] } : {};
  // The shared search drops External-Reference from the scope, which it can only search for a regardingOf filter:
  // left with no type, it would read the scope as "any entity". Such a variable searches nothing.
  const entityTypes = variable.type === 'entity' ? variable.entityTypes ?? [] : [];
  const isSearchable = entityTypes.length === 0 || entityTypes.some((type) => type !== 'External-Reference');
  const [cacheEntities, setCacheEntities] = useState<Record<string, FilterOptionValue[]>>({});
  const [entities, searchEntities] = useSearchEntities({ searchContext: VARIABLE_SEARCH_CONTEXT, searchScope, setInputValues: () => {} });
  const { labels } = useVariableValueLabels(variable, value ? [value] : []);
  const isKillChainPhase = variable.type === 'killChainPhase';
  const killChainPhases = useKillChainPhaseSearch(variable.killChainName);

  const options = isKillChainPhase
    ? killChainPhases.options
    : (isSearchable ? getOptionsFromEntities(entities, searchScope, searchKey) : [])
        // A variable holds an id: neither the "No label" option nor the dynamic @me user can be a value.
        .filter((option) => option.value !== null && option.value !== ME_FILTER_VALUE);
  // Listing the phases needs the knowledge access: without it no default value can be chosen, and the empty list says why.
  const hasListingError = isKillChainPhase && killChainPhases.error;
  const selected = options.find((option) => option.value === value)
    ?? (value ? { value, label: labels.get(value) ?? '', type: variable.type } : null);

  // The kill chain phases are searched with the typed text only, and from an empty text when the field is focused.
  // Picking or clearing also writes the text (the label of the pick): the list then goes back to the whole kill chain.
  const search = (event: SyntheticEvent, text: string, cause: ComboboxChangeCause = 'type') => {
    if (isKillChainPhase) {
      if (cause === 'type') killChainPhases.search(text);
      else killChainPhases.reset();
    } else if (isSearchable) searchEntities(searchKey, cacheEntities, setCacheEntities, event);
  };

  return (
    <Combobox<FilterOptionValue>
      disabled={disabled}
      error={hasListingError}
      clearable={commitOn === 'change'}
      options={options}
      value={selected}
      getOptionLabel={(option) => option.label ?? ''}
      isOptionEqualToValue={(a, b) => a.value === b.value}
      groupBy={variable.type === 'entity' ? (option) => t_i18n(option.group ?? '') : undefined}
      onInputChange={(text, meta) => meta.event && search(meta.event as SyntheticEvent, text, meta.cause)}
      onValueChange={(next) => {
        const nextValue = (next as FilterOptionValue | null)?.value;
        if (nextValue) onChange(nextValue);
        // Clearing is for a form only: in a live filter (the chips) an empty value would mean "unset".
        else if (commitOn === 'change') onChange('');
      }}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField>
        <ComboboxInput onFocus={(event) => search(event, '')} />
        <ComboboxControls>
          {commitOn === 'change' && <ComboboxClear />}
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      {hasListingError && (
        <ComboboxHelperText aria-live="polite">
          {t_i18n('The kill chain phases cannot be listed with your access rights or right now')}
        </ComboboxHelperText>
      )}
      <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={label} />
    </Combobox>
  );
};

export default SearchValueInput;
