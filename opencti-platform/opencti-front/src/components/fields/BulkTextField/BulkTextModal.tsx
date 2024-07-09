import { DialogTitle, DialogContent, Alert, Dialog, DialogActions, TextField, Button } from '@mui/material';
import React, { useEffect, useState } from 'react';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../i18n';

interface BulkTextModalProps {
  open: boolean
  onClose: () => void
  onValidate: (value: string) => void
  formValue: string
}

const MAX_LINES = 50;

const BulkTextModal = ({ open, onClose, onValidate, formValue }: BulkTextModalProps) => {
  const { t_i18n } = useFormatter();
  const [value, setValue] = useState('');
  const nbLines = value.split('\n').filter((v) => !!v).length;

  useEffect(() => {
    setValue(formValue);
  }, [formValue, setValue]);

  const close = () => {
    onClose();
    setValue(formValue);
  };

  const validate = () => {
    onValidate(value);
    close();
  };

  const labelNbLines = nbLines > 0 ? `(${nbLines})` : '';
  const label = `${t_i18n('Entities (one per line)')} ${labelNbLines}`;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      fullWidth={true}
    >
      <DialogTitle>{t_i18n('Create multiple entities')}</DialogTitle>
      <DialogContent style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
        <Alert severity="info" variant="outlined">
          <Typography>
            {t_i18n('If you are adding more than 50 entities, please upload them through')} <a href='/dashboard/data/import'>{t_i18n('Imports')}</a>
          </Typography>
        </Alert>

        <TextField
          label={label}
          variant="outlined"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          fullWidth={true}
          multiline={true}
          rows="5"
        />

        {nbLines > MAX_LINES && (
          <Alert severity="error">
            {t_i18n('You have more than 50 entities')}
          </Alert>
        )}
      </DialogContent>

      <DialogActions>
        <Button onClick={close}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          color="secondary"
          onClick={validate}
          disabled={nbLines === 0 || nbLines > MAX_LINES}
        >
          {t_i18n('Validate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BulkTextModal;
