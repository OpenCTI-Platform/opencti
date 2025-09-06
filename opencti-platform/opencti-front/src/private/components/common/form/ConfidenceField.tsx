import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import InputSliderField from '../../../../components/InputSliderField';
import { useFormatter } from '../../../../components/i18n';
import { GenericContext } from '../model/GenericContextModel';
import useConfidenceLevel from '../../../../utils/hooks/useConfidenceLevel';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
  showAlert?: boolean;
  onSubmit?: (name: string, value: string) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?: readonly (GenericContext | null)[] | null;
  containerStyle?: Record<string, string | number>;
  entityType?: string;
  disabled?: boolean;
  custom_max_level?: number;
  helperText?: string;
}

const ConfidenceField: FunctionComponent<ConfidenceFieldProps> = ({
  name = 'confidence',
  label,
  variant,
  showAlert = true,
  onFocus,
  onSubmit,
  editContext,
  containerStyle,
  entityType,
  disabled,
  custom_max_level,
  helperText,
}) => {
  const { t_i18n } = useFormatter();
  const finalLabel = label || t_i18n('Confidence level');
  const classes = useStyles();
  const { getEffectiveConfidenceLevel } = useConfidenceLevel();
  const userEffectiveMaxConfidence = custom_max_level ?? getEffectiveConfidenceLevel(entityType);

  const Slider = (
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
      maxLimit={userEffectiveMaxConfidence}
      helperText={helperText}
    />
  );

  return showAlert ? (
    <Alert
      classes={{ root: classes.alert, message: classes.message }}
      severity="info"
      icon={false}
      variant="outlined"
      style={{ position: 'relative' }}
      aria-label={finalLabel}
    >
      {Slider}
    </Alert>
  ) : Slider;
};

export default ConfidenceField;
