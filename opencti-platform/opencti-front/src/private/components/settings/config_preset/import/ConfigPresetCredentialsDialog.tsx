import React, { FunctionComponent, useEffect, useState } from 'react';
import { Input, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

export interface ConfigPresetCredential {
  readonly key: string;
  readonly description: string;
  readonly required: boolean;
}

interface ConfigPresetCredentialsDialogProps {
  open: boolean;
  itemLabel: string;
  credentials: ReadonlyArray<ConfigPresetCredential>;
  values: Record<string, string>;
  onClose: () => void;
  onSubmit: (values: Record<string, string>) => void;
}

// The secrets are held in memory and sent with each import, never saved
const ConfigPresetCredentialsDialog: FunctionComponent<ConfigPresetCredentialsDialogProps> = ({ open, itemLabel, credentials, values, onClose, onSubmit }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [draft, setDraft] = useState<Record<string, string>>(values);
  useEffect(() => {
    if (open) {
      setDraft(values);
    }
  }, [open]);
  const isComplete = credentials.every(({ key, required }) => !required || (draft[key] ?? '') !== '');
  return (
    <Dialog open={open} size="small" title={t_i18n('Credentials of {name}', { values: { name: itemLabel } })} onClose={onClose}>
      <Text variant="content-base">{t_i18n('The bundle never contains the credentials: enter them to import this item.')}</Text>
      <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2), marginTop: theme.spacing(2) }}>
        {credentials.map(({ key, description, required }) => (
          <Input
            key={key}
            type="password"
            autoComplete="off"
            label={key}
            required={required}
            helperText={description || undefined}
            value={draft[key] ?? ''}
            onChange={(event) => setDraft((current) => ({ ...current, [key]: event.target.value }))}
          />
        ))}
      </div>
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1), marginTop: theme.spacing(3) }}>
        <Button variant="secondary" onClick={onClose}>{t_i18n('Cancel')}</Button>
        <Button disabled={!isComplete} onClick={() => onSubmit(draft)}>{t_i18n('Save')}</Button>
      </div>
    </Dialog>
  );
};

export default ConfigPresetCredentialsDialog;
