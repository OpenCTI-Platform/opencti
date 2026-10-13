import { useEffect, useState } from 'react';
import { fetchQuery, useRelayEnvironment } from 'react-relay';
import { Select, SelectContent, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@filigran/design-system';
import { vocabularySearchQuery } from '@components/settings/VocabularyQuery';
import type { VocabularyCategory, VocabularyQuery } from '@components/settings/__generated__/VocabularyQuery.graphql';
import { useFormatter } from '../../../i18n';
import useVariableValueLabels from '../useVariableValueLabels';
import type { ValueInputProps } from '../DashboardVariableValueInput';

interface SelectOption {
  value: string;
  label: string;
}

const OptionsSelect = ({ label, value, options, onChange, disabled }: Omit<ValueInputProps, 'variable'> & { options: SelectOption[] }) => (
  <Select value={value} onValueChange={(next) => next && onChange(next)} disabled={disabled}>
    <SelectLabel>{label}</SelectLabel>
    <SelectTrigger className="w-full">
      <SelectValue />
    </SelectTrigger>
    <SelectContent aria-label={label}>
      {options.map((option) => (
        <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>
      ))}
    </SelectContent>
  </Select>
);

export const SelectionValueInput = ({ values, ...props }: ValueInputProps & { values: string[] }) => {
  const { t_i18n } = useFormatter();
  const labels = useVariableValueLabels(props.variable, values);
  const options = values.map((value) => ({ value, label: labels.get(value) ?? t_i18n('Loading') }));
  return <OptionsSelect {...props} options={options} />;
};

export const BooleanValueInput = (props: ValueInputProps) => {
  const { t_i18n } = useFormatter();
  const options = [{ value: 'true', label: t_i18n('True') }, { value: 'false', label: t_i18n('False') }];
  return <OptionsSelect {...props} options={options} />;
};

export const VocabularyValueInput = (props: ValueInputProps) => {
  const environment = useRelayEnvironment();
  const [names, setNames] = useState<string[]>([]);
  const category = props.variable.vocabularyCategory;

  useEffect(() => {
    if (!category) return undefined;
    const subscription = fetchQuery<VocabularyQuery>(
      environment,
      vocabularySearchQuery,
      { category: category as VocabularyCategory },
      { fetchPolicy: 'store-or-network' },
    ).subscribe({
      next: (data) => setNames((data.vocabularies?.edges ?? []).map(({ node }) => node.name)),
    });
    return () => subscription.unsubscribe();
  }, [environment, category]);

  return <OptionsSelect {...props} options={names.map((name) => ({ value: name, label: name }))} />;
};
