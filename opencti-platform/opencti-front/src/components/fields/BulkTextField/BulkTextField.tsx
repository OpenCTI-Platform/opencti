import React, { useContext } from 'react';
import { Alert, Typography } from '@mui/material';
import TextField, { TextFieldProps } from '../../TextField';
import { useFormatter } from '../../i18n';
import { splitMultilines } from '../../../utils/String';
import { CreationFeedbackContext } from '../../../utils/hooks/useCreationFeedback';

type BulkTextFieldProps = TextFieldProps & {
  bulkType?: 'entities' | 'observables';
};

const BulkTextField = ({
  bulkType = 'entities',
  ...props
}: BulkTextFieldProps) => {
  const { t_i18n } = useFormatter();
  const { field: { value }, detectDuplicate } = props;

  const values = splitMultilines(value);
  const hasMultipleValues = values.length > 1;

  // In a container's add panel, the created objects are also added to the container
  const { bulkCreation } = useContext(CreationFeedbackContext);
  const labelValues = { containerType: bulkCreation?.containerType };
  let creationLabel: string;
  if (bulkType === 'entities') {
    creationLabel = bulkCreation
      ? t_i18n('entities will be created and added to the {containerType}', { values: labelValues })
      : t_i18n('entities will be created');
  } else {
    creationLabel = bulkCreation
      ? t_i18n('observables will be created and added to the {containerType}', { values: labelValues })
      : t_i18n('observables will be created');
  }

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
