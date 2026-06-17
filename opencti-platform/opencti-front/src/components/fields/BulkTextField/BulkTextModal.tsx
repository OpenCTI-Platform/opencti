import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { Alert, DialogActions, FormControl, InputLabel, MenuItem, Select, Stack, TextField, Typography } from '@mui/material';
import { useEffect, useMemo, useState } from 'react';
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

const MAX_LINES = 150;

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

  useEffect(() => {
    setValue(formValue);
  }, [formValue, setValue]);

  const close = () => {
    onClose();
    setValue(formValue);
  };

  const noDuplicateNoEmptyValues = useMemo(() => Array.from(new Set(splitMultilines(value))), [value]);
  const nbLines = noDuplicateNoEmptyValues.length;

  const validate = () => {
    onValidate(noDuplicateNoEmptyValues.join('\n'));
    close();
  };

  const isOverLimit = nbLines > MAX_LINES;
  const label = t_i18n('Values (one per line)');

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title={title || t_i18n('Create multiple entities')}
    >
      <Stack gap={2}>
        <Alert severity="info" variant="outlined">
          <Typography variant="body2">
            {t_i18n('If you are adding more than {limit} values, please upload them through', { values: { limit: MAX_LINES } })} <a href="/dashboard/data/import">{t_i18n('Imports')}</a>
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
          error={nbLines > MAX_LINES}
          helperText={t_i18n('{count} / {limit} entries detected', { values: { count: nbLines, limit: MAX_LINES } })}
        />
      </Stack>

      <DialogActions>
        <Button variant="secondary" onClick={close}>
          {t_i18n('Cancel')}
        </Button>
        <Button
          onClick={validate}
          disabled={nbLines === 0 || isOverLimit || (availableKeys && !selectedKey)}
        >
          {!isOverLimit && nbLines > 0
            ? t_i18n('Create {count} objects', { values: { count: nbLines } })
            : t_i18n('Create')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BulkTextModal;
