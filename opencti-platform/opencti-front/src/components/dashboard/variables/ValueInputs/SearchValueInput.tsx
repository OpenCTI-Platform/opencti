import type { SyntheticEvent } from 'react';
import {
  Combobox,
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
import useVariableValueLabels from '../useVariableValueLabels';
import type { ValueInputProps } from '../DashboardVariableValueInput';
import useVariableValueOptions from './useVariableValueOptions';

/**
 * Server side search of the value of an entity pool variable or of an entity type (see useVariableValueOptions).
 */
const SearchValueInput = ({ variable, value, onChange, disabled, label, commitOn }: ValueInputProps) => {
  const { t_i18n } = useFormatter();
  const { options, search, listingError } = useVariableValueOptions(variable);
  const { labels } = useVariableValueLabels(variable, value ? [value] : []);
  const selected = options.find((option) => option.value === value)
    ?? (value ? { value, label: labels.get(value) ?? '', type: variable.type } : null);

  return (
    <Combobox<FilterOptionValue>
      disabled={disabled}
      error={!!listingError}
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
      {listingError && <ComboboxHelperText aria-live="polite">{listingError}</ComboboxHelperText>}
      <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={label} />
    </Combobox>
  );
};

export default SearchValueInput;
