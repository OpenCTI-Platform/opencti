import React, { FunctionComponent, ReactNode } from 'react';
import { Checkbox } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface ConfigPresetCredentialsItemRowProps {
  label: string;
  actions?: ReactNode;
  onOpen: () => void;
}

const ConfigPresetCredentialsItemRow: FunctionComponent<ConfigPresetCredentialsItemRowProps> = ({ label, actions, onOpen }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: theme.spacing(1) }}>
      <Checkbox label={label} checked={false} disabled />
      <div style={{ display: 'flex', alignItems: 'center', gap: theme.spacing(1) }}>
        <Button
          variant="secondary"
          size="small"
          aria-label={t_i18n('Enter the credentials of {name}', { values: { name: label } })}
          title={t_i18n('Enter the credentials to import this item')}
          onClick={onOpen}
        >
          {t_i18n('Credentials required')}
        </Button>
        {actions}
      </div>
    </div>
  );
};

export default ConfigPresetCredentialsItemRow;
