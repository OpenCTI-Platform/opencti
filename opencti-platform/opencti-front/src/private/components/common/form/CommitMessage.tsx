import React, { FunctionComponent, useState } from 'react';
import { Field } from 'formik';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import { useFormatter } from '../../../../components/i18n';
import MarkDownField from '../../../../components/MarkDownField';
import ExternalReferencesField from './ExternalReferencesField';

interface CommitMessageProps {
  id: string
  submitForm: () => void
  disabled: boolean
  validateForm: () => void
  setFieldValue: (field: string, value: any, shouldValidate?: boolean | undefined) => void
  values: { value: string }[]
  noStoreUpdate: boolean
}

const CommitMessage: FunctionComponent<CommitMessageProps> = (
  id,
  submitForm,
  disabled,
  validateForm,
  setFieldValue,
  values,
  noStoreUpdate,
) => {
  const { t } = useFormatter();
  const [open, setOpen] = useState<boolean>(false);
  const handleOpen = () => setOpen(true);
  const handleClose = () => setOpen(false);
  const handleSubmit = () => submitForm();

  return (
    <div>
      {typeof handleClose !== 'function' && (
        <Button
          variant="contained"
          color="primary"
          onClick={handleOpen}
          style={{ marginTop: 20, float: 'right' }}
        >
          {t('Update')}
        </Button>
      )}
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={typeof handleClose !== 'function' ? open : true}
        onClose={handleClose}
        fullWidth={true}
      >
        <DialogTitle>{t('Reference modification')}</DialogTitle>
        <DialogContent>
          <ExternalReferencesField
            name="references"
            style={{ marginTop: 20, width: '100%' }}
            setFieldValue={setFieldValue}
            values={values.value}
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
          <Button
            color="primary"
            onClick={handleSubmit}
            disabled={disabled}
          >
            {t('Validate')}
          </Button>
        </DialogActions>
      </Dialog>
    </div>
  );
};

export default CommitMessage;
