import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import InputSliderField from '../../../../components/InputSliderField';
import { useFormatter } from '../../../../components/i18n';

const useStyles = makeStyles(() => ({
  alert: {
    width: '100%',
    marginTop: 20,
    paddingBottom: 0,
  },
  message: {
    width: '100%',
    overflow: 'visible',
    paddingBottom: 0,
  },
}));

interface ConfidenceFieldProps {
  name?: string;
  label?: string;
  variant?: string;
  onSubmit?: (name: string, value: string) => void;
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
  name = 'confidence',
  label,
  variant,
  onFocus,
  onSubmit,
  editContext,
  containerStyle,
  entityType,
  disabled,
}) => {
  const { t_i18n } = useFormatter();
  const finalLabel = label || t_i18n('Confidence level');
  const classes = useStyles();
  return (
    <Alert
      classes={{ root: classes.alert, message: classes.message }}
      severity="info"
      icon={false}
      variant="outlined"
      style={{ position: 'relative' }}
    >
      <Field
        component={InputSliderField}
        variant={variant}
        containerstyle={containerStyle}
        fullWidth={true}
        entityType={entityType}
        attributeName={name}
        name={name}
        label={finalLabel}
        onFocus={onFocus}
        onSubmit={onSubmit}
        editContext={editContext}
        disabled={disabled}
      />
    </Alert>
  );
};

export default ConfidenceField;
