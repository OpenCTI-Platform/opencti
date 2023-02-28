import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import type { ExternalReferencesValues } from './ExternalReferencesField';
import { ExternalReferencesField } from './ExternalReferencesField';

interface CommitMessageProps {
  id: string
  submitForm: () => Promise<void>
  disabled: boolean
  setFieldValue: (field: string, value: ExternalReferencesValues, shouldValidate?: boolean | undefined) => void
  values: ExternalReferencesValues | undefined
  noStoreUpdate?: boolean
  open: boolean
  handleClose?: () => void
}

const CommitMessage: FunctionComponent<CommitMessageProps> = ({
  id,
  submitForm,
  disabled,
  setFieldValue,
  values,
  open,
  noStoreUpdate,
  handleClose,
}) => {
  const { t } = useFormatter();
  const [controlOpen, setControlOpen] = useState<boolean>(open ?? false);
  const handleOpen = () => setControlOpen(true);
  const handleControlClose = () => setControlOpen(false);

  const validateReferences = (references: ExternalReferencesValues | undefined) => !!references && references.length > 0;

  return (
    <div>
      { !handleClose && (
        <Button variant="contained"
          color="primary"
          onClick={handleOpen}
          disabled={disabled}
          style={{ marginTop: 20, float: 'right' }}>
          {t('Update')}
        </Button>
      )}
        <Dialog PaperProps={{ elevation: 1 }}
          open={handleClose ? open : controlOpen}
          onClose={handleClose ?? handleControlClose }
          fullWidth={true}>
          <DialogTitle>{t('Reference modification')}</DialogTitle>
          <DialogContent>
            <ExternalReferencesField
              name="references"
              style={{ marginTop: 20, width: '100%' }}
              setFieldValue={setFieldValue}
              values={values}
              id={id}
              noStoreUpdate={noStoreUpdate}
            />
            <Field
              component={MarkDownField}
              name="message"
              label={t('Message')}
              fullWidth={true}
              multiline={true}
              rows="2"
              style={{ marginTop: 20 }}
            />
          </DialogContent>
          <DialogActions>
            <Button color="primary"
              onClick={submitForm}
              disabled={disabled || !validateReferences(values)}>
              {t('Validate')}
            </Button>
          </DialogActions>
        </Dialog>
    </div>
  );
};

export default CommitMessage;
