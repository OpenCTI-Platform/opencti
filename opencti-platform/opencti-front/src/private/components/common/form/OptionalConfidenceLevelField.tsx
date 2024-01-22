import React, { FunctionComponent, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
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

interface OptionalConfidenceLevelFieldProps {
  name: string;
  label?: string;
  variant?: string;
  onSubmit: (name: string, value: string | null) => void;
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

const OptionalConfidenceLevelField: FunctionComponent<OptionalConfidenceLevelFieldProps> = ({
  name,
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
  const { setFieldValue, initialValues } = useFormikContext<Record<string, boolean>>();

  const [switchValue, setSwitchValue] = useState(initialValues[name]); // Default switch value

  const handleSwitchChange = () => {
    if (switchValue) {
      setFieldValue(name, null);
      onSubmit(name, null);
    } else {
      setFieldValue(name, 100);
      onSubmit(name, '100');
    }
    setSwitchValue(!switchValue);
  };
  return (
    <Alert
      classes={{ root: classes.alert, message: classes.message }}
      severity="info"
      icon={false}
      variant="outlined"
      style={{ position: 'relative' }}
    >
      <FormControlLabel
        control={<Switch checked={switchValue} onChange={handleSwitchChange} />}
        label="Disable Confidence Level"
      />
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
        disabled={!switchValue || disabled}
      />
    </Alert>
  );
};

export default OptionalConfidenceLevelField;
