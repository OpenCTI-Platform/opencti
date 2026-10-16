import type { SyntheticEvent } from 'react';
import {
  Combobox,
  ComboboxChips,
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
import type { DashboardVariableShape } from '../DashboardVariableValueInput';
import useVariableValueOptions from './useVariableValueOptions';
import useVocabularyNames from './useVocabularyNames';

export interface SelectionValuesInputProps {
  variable: DashboardVariableShape;
  values: string[];
  onChange: (values: string[]) => void;
  label: string;
  disabled?: boolean;
  error?: string;
  onBlur?: () => void;
}

/**
 * Input of the values of a selection restriction: the values a variable is restricted to, searched as the value of
 * the variable is (useVariableValueOptions), or picked among the vocabularies of its category.
 */
const SelectionValuesInput = ({ variable, values, onChange, label, disabled, error, onBlur }: SelectionValuesInputProps) => {
  const { t_i18n } = useFormatter();
  const isVocabulary = variable.type === 'vocabulary';
  const { options: searchOptions, search } = useVariableValueOptions(variable);
  const vocabularyNames = useVocabularyNames(isVocabulary ? variable.vocabularyCategory : undefined);
  const { labels } = useVariableValueLabels(variable, values);
  const options: FilterOptionValue[] = isVocabulary
    ? vocabularyNames.map((name) => ({ value: name, label: name, type: 'Vocabulary' }))
    : searchOptions;
  // A value no longer found (deleted, not visible) keeps a chip, labelled `Restricted`, so that it can be removed.
  const selected = values.map((value) => options.find((option) => option.value === value)
    ?? { value, label: labels.get(value) ?? t_i18n('Loading'), type: variable.type });

  const runSearch = (event: SyntheticEvent, text: string, cause?: Parameters<typeof search>[2]) => {
    if (!isVocabulary) search(event, text, cause);
  };

  return (
    <Combobox<FilterOptionValue>
      multiple
      closeOnSelect={false}
      disabled={disabled}
      error={!!error}
      options={options}
      value={selected}
      getOptionLabel={(option) => option.label ?? ''}
      isOptionEqualToValue={(a, b) => a.value === b.value}
      groupBy={variable.type === 'entity' ? (option) => t_i18n(option.group ?? '') : undefined}
      onInputChange={(text, meta) => meta.event && runSearch(meta.event as SyntheticEvent, text, meta.cause)}
      onValueChange={(next) => {
        const picked = (next as FilterOptionValue[] | null) ?? [];
        onChange(picked.flatMap((option) => (option.value ? [option.value] : [])));
      }}
    >
      <ComboboxLabel>{label}</ComboboxLabel>
      <ComboboxField>
        <ComboboxChips aria-label={label} />
        <ComboboxInput onFocus={(event) => runSearch(event, '')} onBlur={onBlur} />
        <ComboboxControls>
          <ComboboxTrigger />
        </ComboboxControls>
      </ComboboxField>
      <ComboboxContent emptyMessage={t_i18n('No available options')} listAriaLabel={label} />
      {error && <ComboboxHelperText>{error}</ComboboxHelperText>}
    </Combobox>
  );
};

export default SelectionValuesInput;
