import { ChangeEvent, KeyboardEvent, useState } from 'react';
import { Input } from '@filigran/design-system';
import { useFormatter } from '../../../i18n';
import { toVariableToken } from '../../dashboardVariablesResolution';
import type { ValueInputProps } from '../DashboardVariableValueInput';

const VARIABLE_TOKEN_PREFIX = toVariableToken('');

/**
 * Free input of a text or numeric value. The typed text is kept locally so the field can be emptied or hold
 * an invalid value while typing; only a valid value is emitted.
 * With `commitOn="change"` the value is emitted on each keystroke, an emptied field as an empty value.
 * With `commitOn="blur"` (as `DateValueInput`) it is emitted once, on Enter or blur, only when it changed
 * and never empty.
 */
const TextValueInput = ({ variable, value, onChange, disabled, label, commitOn }: ValueInputProps) => {
  const { t_i18n } = useFormatter();
  const isNumeric = variable.type === 'numeric';
  const [draft, setDraft] = useState(value);
  const [received, setReceived] = useState(value);
  // A value set from outside (reset, other device) replaces the typed text.
  if (value !== received) {
    setReceived(value);
    // A blank draft was emitted as an empty value: it is not replaced by the echo, so typing spaces is not undone.
    if (!(value === '' && draft.trim() === '')) setDraft(value);
  }
  const isToken = draft.includes(VARIABLE_TOKEN_PREFIX);

  const isValid = (next: string) => (
    next.trim() !== '' && !next.includes(VARIABLE_TOKEN_PREFIX) && (!isNumeric || Number.isFinite(Number(next)))
  );

  const handleChange = (event: ChangeEvent<HTMLInputElement>) => {
    const next = event.target.value;
    setDraft(next);
    if (commitOn !== 'change') return;
    // Emptied (or blank): a form must forget its previous value, which the field no longer shows. Nothing is emitted
    // for a refused value (referencing a variable, or not a number): its error is shown instead.
    if (next.trim() === '') onChange('');
    else if (isValid(next)) onChange(next);
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
