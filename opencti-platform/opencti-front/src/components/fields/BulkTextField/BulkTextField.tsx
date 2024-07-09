import React from 'react';
import { FieldProps } from 'formik';
import { Alert, Typography } from '@mui/material';
import TextField from '../../TextField';
import { useFormatter } from '../../i18n';

// TODO make TextField component as typescript and reuse its props
interface BulkTextFieldProps extends FieldProps<string> {
  [key: string]: unknown
}

const BulkTextField = (props: BulkTextFieldProps) => {
  const { t_i18n } = useFormatter();
  const { field: { value }, detectDuplicate } = props;

  const values = value.split('\n');
  const hasMultipleValues = values.length > 1;

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
            {values.length} {t_i18n('entities will be created')}
          </Typography>
        </Alert>
      )}
    </>
  );
};

export default BulkTextField;
