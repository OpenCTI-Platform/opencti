import React, { FunctionComponent, useState } from 'react';
import { Field, useFormikContext } from 'formik';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Tooltip from '@mui/material/Tooltip';
import makeStyles from '@mui/styles/makeStyles';
import FormControlLabel from '@mui/material/FormControlLabel';
import Switch from '@mui/material/Switch';
import { InformationOutline } from 'mdi-material-ui';
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
  onSubmit?: (name: string, value: string | null) => void;
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

  const [switchValue, setSwitchValue] = useState(Number.isInteger(initialValues[name])); // Default switch value

  const handleSwitchChange = async () => {
    if (switchValue) {
      await setFieldValue(name, null);
      onSubmit?.(name, null);
    } else {
      await setFieldValue(name, 100);
      onSubmit?.(name, '100');
    }
    setSwitchValue(!switchValue);
  };
  return (
    <Alert
      classes={{ root: classes.alert, message: classes.message }}
      severity="info"
      icon={false}
      variant="outlined"
      sx={{ position: 'relative' }}
    >
      <Box sx={{ display: 'flex', alignItems: 'center' }}>
        <FormControlLabel
          control={<Switch checked={switchValue} onChange={handleSwitchChange} />}
          label={t_i18n('Enable user max confidence level')}
          sx={{ marginRight: 1 }}
        />
        <Tooltip
          sx={{ zIndex: 2 }}
          title={t_i18n('The user\'s max confidence level overrides the max confidence that might be set at groups or organizations level.')}
        >
          <InformationOutline fontSize="small" color="primary" />
        </Tooltip>
      </Box>
      <Field
        component={InputSliderField}
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
        variant="edit"
      />
    </Alert>
  );
};

export default OptionalConfidenceLevelField;
