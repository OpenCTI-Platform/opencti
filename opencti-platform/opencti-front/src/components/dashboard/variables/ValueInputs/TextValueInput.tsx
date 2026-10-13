import { ChangeEvent, KeyboardEvent, useState } from 'react';
import { Input } from '@filigran/design-system';
import { useFormatter } from '../../../i18n';
import { toVariableToken } from '../../dashboardVariablesResolution';
import type { ValueInputProps } from '../DashboardVariableValueInput';

const VARIABLE_TOKEN_PREFIX = toVariableToken('');

/**
 * Free input of a text or numeric value. The typed text is kept locally so the field can be emptied or hold
 * an invalid value while typing; only a valid value is emitted.
 * With `commitOn="change"` the value is emitted on each keystroke. With `commitOn="blur"` (as `DateValueInput`)
 * it is emitted once, on Enter or blur, and only when it changed.
 */
const TextValueInput = ({ variable, value, onChange, disabled, label, commitOn }: ValueInputProps) => {
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

  const isValid = (next: string) => (
    next.trim() !== '' && !next.includes(VARIABLE_TOKEN_PREFIX) && (!isNumeric || Number.isFinite(Number(next)))
  );

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const next = event.target.value;
    setDraft(next);
    if (commitOn === 'change' && isValid(next)) onChange(next);
  };

  const commit = () => {
    if (commitOn === 'blur' && draft !== value && isValid(draft)) onChange(draft);
  };

  const handleKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter') commit();
  };

  return (
    <Input
      type={isNumeric ? 'number' : 'text'}
      label={label}
      value={draft}
      onChange={handleChange}
      onKeyDown={handleKeyDown}
      onBlur={commit}
      disabled={disabled}
      error={isToken ? t_i18n('A value cannot reference another variable') : undefined}
    />
  );
};

export default TextValueInput;
