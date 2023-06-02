import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import InputSliderField from '../../../../components/InputSliderField';
import { useFormatter } from '../../../../components/i18n';

interface ConfidenceFieldProps {
  variant?: string;
  onSubmit?: (name: string, value: string | number | number[]) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?:
  | readonly ({
    readonly focusOn: string | null;
    readonly name: string;
  } | null)[]
  | null;
  containerStyle?: Record<string, string | number>;
  entityType: string;
  disabled?: boolean;
}

const ConfidenceField: FunctionComponent<ConfidenceFieldProps> = ({
  variant,
  onFocus,
  onSubmit,
  editContext,
  containerStyle,
  entityType,
  disabled,
}) => {
  const { t } = useFormatter();
  return (
    <Field
      component={InputSliderField}
      variant={variant}
      containerstyle={containerStyle}
      fullWidth={true}
      entityType={entityType}
      attributeName="confidence"
      name={'confidence'}
      label={t('Confidence level')}
      onFocus={onFocus}
      onSubmit={onSubmit}
      editContext={editContext}
      disabled={disabled}
    />
  );
};

export default ConfidenceField;
