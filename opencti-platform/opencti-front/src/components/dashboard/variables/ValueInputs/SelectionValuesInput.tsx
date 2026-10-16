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
  label: string;
  disabled?: boolean;
  error?: string;
}

/**
 * Input of the values of a selection restriction: the values a variable is restricted to, searched as the value of
 * the variable is (useVariableValueOptions), or picked among the vocabularies of its category.
 */
const SelectionValuesInput = ({ variable, values, onChange, label, disabled, error }: SelectionValuesInputProps) => {
  const { t_i18n } = useFormatter();
  const isVocabulary = variable.type === 'vocabulary';
  const { options: searchOptions, search } = useVariableValueOptions(variable);
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
  // FDS-WORKAROUND #71: dropped once the chips are no longer keyed by label (fds-migration/LIBRARY-FEEDBACK.md).
  const seenLabels = new Map<string, number>();
  const selected = values.map((value) => {
    const option = options.find((candidate) => candidate.value === value)
      ?? { value, label: labels.get(value) ?? knownLabels.current.get(value) ?? t_i18n('Loading'), type: variable.type };
    const count = (seenLabels.get(option.label) ?? 0) + 1;
    seenLabels.set(option.label, count);
    return count === 1 ? option : { ...option, label: `${option.label} (${count})` };
  });

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
        <ComboboxInput onFocus={(event) => runSearch(event, '')} />
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
