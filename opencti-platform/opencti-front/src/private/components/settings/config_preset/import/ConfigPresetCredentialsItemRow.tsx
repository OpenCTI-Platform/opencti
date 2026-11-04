import React, { FunctionComponent } from 'react';
import { Checkbox, Chip } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';
import { onActivationKey } from '../../../../../utils/domEvent';

interface ConfigPresetCredentialsItemRowProps {
  label: string;
  onOpen: () => void;
}

const ConfigPresetCredentialsItemRow: FunctionComponent<ConfigPresetCredentialsItemRowProps> = ({ label, onOpen }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div
      role="button"
      tabIndex={0}
      aria-label={t_i18n('Enter the credentials of {name}', { values: { name: label } })}
      title={t_i18n('Enter the credentials to import this item')}
      style={{ cursor: 'pointer' }}
      onClick={onOpen}
      onKeyDown={onActivationKey(onOpen)}
    >
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1), pointerEvents: 'none' }}>
        <Checkbox label={label} checked={false} disabled />
        <Chip label={t_i18n('Credentials required')} severity="warning" />
      </div>
    </div>
  );
};

export default ConfigPresetCredentialsItemRow;
