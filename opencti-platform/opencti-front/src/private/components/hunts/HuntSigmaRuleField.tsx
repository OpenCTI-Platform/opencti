import React from 'react';
import { Field, getIn, useFormikContext } from 'formik';
import { HuntCodeEditorField } from './HuntCodeEditor';
import HuntSigmaValidation from './HuntSigmaValidation';
import { HuntAIAction } from './HuntAIAssist';

interface HuntSigmaRuleFieldProps {
  /** The form value it edits: the rule of the form, or one rule of a list (sigma_rules.2) */
  name?: string;
  label: string;
  helperText: string;
  placeholder: string;
  minRows?: number;
  maxRows?: number;
  disabled?: boolean;
  /** "Generate with AI" writes the rule of the form: offered on that rule only */
  aiAssist?: boolean;
  /** An action of the label row, for instance the removal of a rule from a list */
  action?: React.ReactNode;
  testId: string;
}

/**
 * A Sigma rule of a hunt: its editor, with the "Generate with AI" of the form in the label row (XTM One proposes
 * the rule from the whole form, the analyst accepts it), and the live validation of the platform under it.
 */
const HuntSigmaRuleField = ({ name = 'sigma_rule', label, helperText, placeholder, minRows = 10, maxRows, disabled = false, aiAssist = true, action, testId }: HuntSigmaRuleFieldProps) => {
  const { values } = useFormikContext<Record<string, unknown>>();
  const aiAction = aiAssist ? <HuntAIAction request={{ kind: 'sigma_rule' }} disabled={disabled} testId="hunt-sigma-generate" /> : null;
  return (
    <>
      <Field
        component={HuntCodeEditorField}
        name={name}
        label={label}
        language="yaml"
        placeholder={placeholder}
        minRows={minRows}
        maxRows={maxRows}
        disabled={disabled}
        helperText={helperText}
        labelAction={aiAction || action ? <>{aiAction}{action}</> : undefined}
        testId={testId}
      />
      <HuntSigmaValidation sigmaRule={(getIn(values, name) as string | undefined) ?? ''} />
    </>
  );
};

export default HuntSigmaRuleField;
