import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import Alert from '@mui/material/Alert';
import makeStyles from '@mui/styles/makeStyles';
import InputScaleField from '../../../../components/InputScaleField';
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
  onSubmit?: (name: string, value: string) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?: readonly (GenericContext | null)[] | null;
  containerStyle?: Record<string, string | number>;
  entityType: string;
  disabled?: boolean;
}

const ConfidenceField: FunctionComponent<ConfidenceFieldProps> = ({
  name = 'confidence',
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
  const { getEffectiveConfidenceLevel } = useConfidenceLevel();
  const userEffectiveMaxConfidence = getEffectiveConfidenceLevel(entityType);
  return (
    <Alert
      classes={{ root: classes.alert, message: classes.message }}
      severity="info"
      icon={false}
      variant="outlined"
      style={{ position: 'relative', ...(containerStyle || {}) }}
      aria-label={finalLabel}
    >
      <Field
        component={InputScaleField}
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
      />
    </Alert>
  );
};

export default ConfidenceField;
