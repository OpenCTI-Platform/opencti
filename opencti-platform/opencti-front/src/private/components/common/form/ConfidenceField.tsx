import React, { FunctionComponent } from 'react';
import { Field } from 'formik';
import Alert from '@mui/material/Alert';
import AlertTitle from '@mui/material/AlertTitle';
import makeStyles from '@mui/styles/makeStyles';
import InputSliderField from '../../../../components/InputSliderField';
import { useFormatter } from '../../../../components/i18n';
import { SCALE_KEYS } from '../../../../utils/hooks/useScale';
import { Option } from './ReferenceField';

const useStyles = makeStyles(() => ({
  alert: {
    width: '100%',
    marginTop: 20,
  },
  message: {
    width: '100%',
    overflow: 'hidden',
  },
}));

interface ConfidenceFieldProps {
  variant?: string
  onSubmit?: (name: string, value: string | number | number[] | Option) => void;
  onFocus?: (name: string, value: string) => void;
  editContext?: unknown;
  containerStyle?: Record<string, string | number>;
  entityType: string,
}

const ConfidenceField: FunctionComponent<ConfidenceFieldProps> = ({
  variant,
  onFocus,
  onSubmit,
  editContext,
  containerStyle,
  entityType,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  return (
    <div style={{ padding: '20px 0' }}>
      <Alert
        classes={{ root: classes.alert, message: classes.message }}
        severity="info"
        icon={false}
        variant="outlined"
        style={{ position: 'relative' }}>
        <AlertTitle>
          {t('Confidence')}
        </AlertTitle>
      <Field
        component={InputSliderField}
        variant={variant}
        containerstyle={containerStyle}
        fullWidth={true}
        entityType={entityType}
        scaleType={SCALE_KEYS.confidence}
        name={'confidence'}
        label={t('Confidence level')}
        onFocus={onFocus}
        onSubmit={onSubmit}
        editContext={editContext}
      />
      </Alert>
    </div>
  );
};

export default ConfidenceField;
