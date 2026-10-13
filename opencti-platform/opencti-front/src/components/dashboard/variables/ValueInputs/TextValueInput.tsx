import { ChangeEvent, useState } from 'react';
import { Input } from '@filigran/design-system';
import { useFormatter } from '../../../i18n';
import { toVariableToken } from '../../dashboardVariablesResolution';
import type { ValueInputProps } from '../DashboardVariableValueInput';

const VARIABLE_TOKEN_PREFIX = toVariableToken('');

/**
 * Free input of a text or numeric value. The typed text is kept locally so the field can be emptied or hold
 * an invalid value while typing; only a valid value is emitted.
 */
const TextValueInput = ({ variable, value, onChange, disabled, label }: ValueInputProps) => {
  const { t_i18n } = useFormatter();
  const isNumeric = variable.type === 'numeric';
  const [draft, setDraft] = useState(value);
  const [received, setReceived] = useState(value);
  // A value set from outside (reset, other device) replaces the typed text.
  if (value !== received) {
    setReceived(value);
    setDraft(value);
  }
  const isToken = draft.includes(VARIABLE_TOKEN_PREFIX);

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const next = event.target.value;
    setDraft(next);
    const isValid = next.trim() !== '' && !next.includes(VARIABLE_TOKEN_PREFIX) && (!isNumeric || Number.isFinite(Number(next)));
    if (isValid) onChange(next);
  };

  return (
    <Input
      type={isNumeric ? 'number' : 'text'}
      label={label}
      value={draft}
      onChange={handleChange}
      disabled={disabled}
      error={isToken ? t_i18n('A value cannot reference another variable') : undefined}
    />
  );
};

export default TextValueInput;
