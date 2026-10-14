import { SyntheticEvent, useState } from 'react';
import { Combobox, ComboboxClear, ComboboxContent, ComboboxControls, ComboboxField, ComboboxInput, ComboboxLabel, ComboboxTrigger } from '@filigran/design-system';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import { useFormatter } from '../../../i18n';
import useSearchEntities from '../../../../utils/filters/useSearchEntities';
import { getOptionsFromEntities } from '../../../../utils/filters/SearchEntitiesUtil';
import { ME_FILTER_VALUE } from '../../../../utils/filters/filtersUtils';
import useVariableValueLabels from '../useVariableValueLabels';
import { VARIABLE_SEARCH_CONTEXT, VARIABLE_TYPE_SEARCH } from '../variableTypeSearch';
import type { ValueInputProps } from '../DashboardVariableValueInput';

/**
 * Server side search of the value of an entity pool variable (entity, label, marking, user, group, status,
 * kill chain phase) or of an entity type, through the same search as the filters.
 */
const SearchValueInput = ({ variable, value, onChange, disabled, label, commitOn }: ValueInputProps) => {
  const { t_i18n } = useFormatter();
  const searchKey = VARIABLE_TYPE_SEARCH[variable.type] ?? 'id';
  const searchScope = variable.type === 'entity' ? { [searchKey]: variable.entityTypes ?? [] } : {};
  const [cacheEntities, setCacheEntities] = useState<Record<string, FilterOptionValue[]>>({});
  const [entities, searchEntities] = useSearchEntities({ searchContext: VARIABLE_SEARCH_CONTEXT, searchScope, setInputValues: () => {} });
  const labels = useVariableValueLabels(variable, value ? [value] : []);

  const { killChainName } = variable;
  const options = getOptionsFromEntities(entities, searchScope, searchKey)
    // A variable holds an id: neither the "No label" option nor the dynamic @me user can be a value.
    .filter((option) => option.value !== null && option.value !== ME_FILTER_VALUE)
    // Kill chain phase options are labelled `[kill chain name] phase name`.
    .filter((option) => variable.type !== 'killChainPhase' || !killChainName || option.label.startsWith(`[${killChainName}] `));
  const selected = options.find((option) => option.value === value)
    ?? (value ? { value, label: labels.get(value) ?? '', type: variable.type } : null);

  const search = (event: SyntheticEvent) => searchEntities(searchKey, cacheEntities, setCacheEntities, event);

  return (
    <Combobox<FilterOptionValue>
      disabled={disabled}
      clearable={commitOn === 'change'}
      options={options}
      value={selected}
      getOptionLabel={(option) => option.label ?? ''}
      isOptionEqualToValue={(a, b) => a.value === b.value}
      groupBy={variable.type === 'entity' ? (option) => t_i18n(option.group ?? '') : undefined}
      onInputChange={(_, meta) => meta.event && search(meta.event as SyntheticEvent)}
      onValueChange={(next) => {
        const nextValue = (next as FilterOptionValue | null)?.value;
        if (nextValue) onChange(nextValue);
        // Clearing is for a form only: in a live filter (the chips) an empty value would mean "unset".
        else if (commitOn === 'change') onChange('');
      }}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField>
        <ComboboxInput onFocus={search} />
        <ComboboxControls>
          {commitOn === 'change' && <ComboboxClear />}
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={label} />
    </Combobox>
  );
};

export default SearchValueInput;
