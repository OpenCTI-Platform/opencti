import React from 'react';
import { Field, useFormikContext } from 'formik';
import { HuntCodeEditorField } from './HuntCodeEditor';
import HuntSigmaValidation from './HuntSigmaValidation';
import { HuntAIAction } from './HuntAIAssist';

interface SigmaRuleValues {
  sigma_rule: string;
}

interface HuntSigmaRuleFieldProps {
  label: string;
  helperText: string;
  placeholder: string;
  minRows?: number;
  maxRows?: number;
  disabled?: boolean;
  testId: string;
}

/**
 * The Sigma rule of a hunt: its editor, with the "Generate with AI" of the form in the label row (XTM One proposes
 * the rule from the whole form, the analyst accepts it), and the live validation of the platform under it.
 */
const HuntSigmaRuleField = ({ label, helperText, placeholder, minRows = 10, maxRows, disabled = false, testId }: HuntSigmaRuleFieldProps) => {
  const { values } = useFormikContext<SigmaRuleValues>();
  return (
    <>
      <Field
        component={HuntCodeEditorField}
        name="sigma_rule"
        label={label}
        language="yaml"
        placeholder={placeholder}
        minRows={minRows}
        maxRows={maxRows}
        disabled={disabled}
        helperText={helperText}
        labelAction={<HuntAIAction request={{ kind: 'sigma_rule' }} disabled={disabled} testId="hunt-sigma-generate" />}
        testId={testId}
      />
      <HuntSigmaValidation sigmaRule={values.sigma_rule ?? ''} />
    </>
  );
};

export default HuntSigmaRuleField;
