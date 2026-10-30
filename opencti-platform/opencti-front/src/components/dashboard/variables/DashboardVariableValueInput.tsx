import type { DashboardVariable } from '../dashboard-types';
import { useFormatter } from '../../i18n';
import { BooleanValueInput, SelectionValueInput, VocabularyValueInput } from './ValueInputs/SelectValueInputs';
import TextValueInput from './ValueInputs/TextValueInput';
import DateValueInput from './ValueInputs/DateValueInput';
import SearchValueInput from './ValueInputs/SearchValueInput';

// A variable or a draft of one: the type parameters are optional until the draft is complete.
export type DashboardVariableShape = Pick<DashboardVariable, 'type' | 'restriction'> & {
  vocabularyCategory?: string;
  killChainName?: string;
  entityTypes?: string[];
};

export interface DashboardVariableValueInputProps {
  variable: DashboardVariableShape;
  value: string;
  // Never called with a value referencing a variable. Called with an empty value only when the user clears the field
  // and `commitOn` is `change`: a form then forgets its value. With `blur` an empty value is never emitted.
  onChange: (value: string) => void;
  disabled?: boolean;
  // Visible label of the field, `Value` by default.
  label?: string;
  // When a typed text or number is emitted: on each keystroke (default, a form field) or once on Enter or blur
  // (a live filter, such as the chips, where each value re-queries the widgets). Other kinds of input ignore it.
  commitOn?: 'change' | 'blur';
}

export type ValueInputProps = Required<Omit<DashboardVariableValueInputProps, 'disabled'>> & { disabled?: boolean };

/**
 * Input of the value of a dashboard variable, by family of type.
 * A selection restriction narrows every family to its list of values. A filters restriction (entity variables only)
 * narrows the search to the entities that match its rule.
 */
const DashboardVariableValueInput = ({ label, commitOn = 'change', ...props }: DashboardVariableValueInputProps) => {
  const { t_i18n } = useFormatter();
  const inputProps = { ...props, commitOn, label: label ?? t_i18n('Value') };
  const { restriction, type } = props.variable;
  if (restriction.mode === 'selection') {
    return <SelectionValueInput {...inputProps} values={restriction.values} />;
  }
  switch (type) {
    case 'boolean':
      return <BooleanValueInput {...inputProps} />;
    case 'numeric':
    case 'text':
      return <TextValueInput {...inputProps} />;
    case 'date':
      return <DateValueInput {...inputProps} />;
    case 'vocabulary':
      return <VocabularyValueInput {...inputProps} />;
    default:
      return <SearchValueInput {...inputProps} />;
  }
};

export default DashboardVariableValueInput;
