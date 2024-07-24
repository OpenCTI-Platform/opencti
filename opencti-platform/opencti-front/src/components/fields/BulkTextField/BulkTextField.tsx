import React from 'react';
import { FieldProps } from 'formik';
import { Alert, Typography } from '@mui/material';
import TextField from '../../TextField';
import { useFormatter } from '../../i18n';
import { splitMultilines } from '../../../utils/String';

// TODO make TextField component as typescript and reuse its props
interface BulkTextFieldProps extends FieldProps<string> {
  [key: string]: unknown
  bulkType?: 'entities' | 'observables'
}

const BulkTextField = ({
  bulkType = 'entities',
  ...props
}: BulkTextFieldProps) => {
  const { t_i18n } = useFormatter();
  const { field: { value }, detectDuplicate } = props;

  const values = splitMultilines(value);
  const hasMultipleValues = values.length > 1;

  const creationLabel = bulkType === 'entities'
    ? t_i18n('entities will be created')
    : t_i18n('observables will be created');

  return (
    <>
      <TextField
        {...props}
        multiline={hasMultipleValues}
        disabled={hasMultipleValues}
        maxRows={5}
        detectDuplicate={hasMultipleValues ? undefined : detectDuplicate}
      />

      {hasMultipleValues && (
        <Alert severity="info" sx={{ marginTop: 2 }}>
          <Typography>
            {values.length} {creationLabel}
          </Typography>
        </Alert>
      )}
    </>
  );
};

export default BulkTextField;
