import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Alert, DialogActions, FormControl, InputLabel, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { splitMultilines } from '../../../utils/String';
import { useFormatter } from '../../i18n';

interface BulkTextModalProps {
  open: boolean;
  onClose: () => void;
  onValidate: (value: string) => void;
  formValue: string;
  title?: string;
  selectedKey?: string;
  availableKeys?: string[];
  onSelectKey?: (key: string) => void;
}

const MAX_LINES = 50;

const BulkTextModal = ({
  open,
  onClose,
  onValidate,
  formValue,
  title,
  selectedKey,
  availableKeys,
  onSelectKey,
}: BulkTextModalProps) => {
  const { t_i18n } = useFormatter();
  const [value, setValue] = useState('');
  const nbLines = splitMultilines(value).length;

  useEffect(() => {
    setValue(formValue);
  }, [formValue, setValue]);

  const close = () => {
    onClose();
    setValue(formValue);
  };

  const validate = () => {
    const noDuplicateNoEmpty = Array.from(new Set(splitMultilines(value)));
    onValidate(noDuplicateNoEmpty.join('\n'));
    close();
  };

  const labelNbLines = nbLines > 0 ? `(${nbLines})` : '';
  const label = `${t_i18n('Values (one per line)')} ${labelNbLines}`;

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title || t_i18n('Create multiple entities')}
    >
      <Stack gap={2}>
        <Alert severity="info" variant="outlined">
          <Typography variant="body2">
            {t_i18n('If you are adding more than 50 values, please upload them through')} <a href="/dashboard/data/import">{t_i18n('Imports')}</a>
          </Typography>
        </Alert>

        {availableKeys && (
          <FormControl>
            <InputLabel id="bulk-text-modal-key-select">
              {t_i18n('Attribute used to create multiple')}
            </InputLabel>
            <Select
              labelId="bulk-text-modal-key-select"
              label={t_i18n('Attribute used to create multiple')}
              value={selectedKey ?? ''}
              onChange={(event) => onSelectKey?.(event.target.value)}
              fullWidth={true}
            >
              {availableKeys?.map((key) => (
                <MenuItem key={key} value={key}>{key}</MenuItem>
              ))}
            </Select>
          </FormControl>
        )}

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
            {t_i18n('You have more than 50 values')}
          </Alert>
        )}
      </Stack>

      <DialogActions>
        <Button variant="secondary" onClick={close}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={validate}
          disabled={nbLines === 0 || nbLines > MAX_LINES || (availableKeys && !selectedKey)}
        >
          {t_i18n('Validate')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BulkTextModal;
