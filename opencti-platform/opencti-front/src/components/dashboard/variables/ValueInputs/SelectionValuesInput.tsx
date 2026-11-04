import { type SyntheticEvent, useEffect, useRef } from 'react';
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
  onBlur?: () => void;
  label: string;
  disabled?: boolean;
  error?: string;
}

/**
 * Input of the values of a selection restriction: the values a variable is restricted to, searched as the value of
 * the variable is (useVariableValueOptions), or picked among the vocabularies of its category.
 */
const SelectionValuesInput = ({ variable, values, onChange, onBlur, label, disabled, error }: SelectionValuesInputProps) => {
  const { t_i18n } = useFormatter();
  const isVocabulary = variable.type === 'vocabulary';
  const { options: searchOptions, search, listingError } = useVariableValueOptions(variable);
  const helperText = error ?? listingError;
  const vocabularyNames = useVocabularyNames(isVocabulary ? variable.vocabularyCategory : undefined);
  const { labels } = useVariableValueLabels(variable, values);
  // Each pick resolves the labels of the whole selection again: the labels already known stay shown meanwhile,
  // instead of every chip going back to `Loading`.
  const knownLabels = useRef(new Map<string, string>());
  // Recorded once rendered: a render React discards records nothing.
  useEffect(() => {
    labels.forEach((name, value) => knownLabels.current.set(value, name));
  }, [labels]);
  const options: FilterOptionValue[] = isVocabulary
    ? vocabularyNames.map((name) => ({ value: name, label: name, type: 'Vocabulary' }))
    : searchOptions;
  // A value no longer found (deleted, not visible) keeps a chip, labelled `Restricted`, so that it can be removed.
  // The library keys its chips by label: a label already taken (values still loading, two restricted values,
  // two entities of the same name) is numbered, or React would leave stale chips behind.
  // FDS-WORKAROUND #72: dropped once the chips are no longer keyed by label (fds-migration/LIBRARY-FEEDBACK.md).
  // A number is taken until the label is free: `Acme`, `Acme` and `Acme (2)` give `Acme`, `Acme (2)`, `Acme (2) (2)`.
  const usedLabels = new Set<string>();
  const selected = values.map((value) => {
    const option = options.find((candidate) => candidate.value === value)
      ?? { value, label: labels.get(value) ?? knownLabels.current.get(value) ?? t_i18n('Loading'), type: variable.type };
    let label = option.label;
    for (let count = 2; usedLabels.has(label); count += 1) label = `${option.label} (${count})`;
    usedLabels.add(label);
    return label === option.label ? option : { ...option, label };
  });

  const runSearch = (event: SyntheticEvent, text: string, cause?: Parameters<typeof search>[2]) => {
    if (!isVocabulary) search(event, text, cause);
  };

  return (
    <Combobox<FilterOptionValue>
      multiple
      closeOnSelect={false}
      disabled={disabled}
      error={!!helperText}
      options={options}
      value={selected}
      getOptionLabel={(option) => option.label ?? ''}
      isOptionEqualToValue={(a, b) => a.value === b.value}
      groupBy={variable.type === 'entity' ? (option) => t_i18n(option.group ?? '') : undefined}
      onInputChange={(text, meta) => meta.event && runSearch(meta.event as SyntheticEvent, text, meta.cause)}
      onValueChange={(next) => {
        const picked = (next as FilterOptionValue[] | null) ?? [];
        // The label of a pick is known now, before the labels of the new selection resolve. Taken from the search
        // options: a chip label may carry the number of a duplicate.
        options.forEach((option) => {
          if (option.value && picked.some((pick) => pick.value === option.value)) knownLabels.current.set(option.value, option.label);
        });
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
      {helperText && <ComboboxHelperText aria-live="polite">{helperText}</ComboboxHelperText>}
    </Combobox>
  );
};

export default SelectionValuesInput;
