import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface ConfigPresetImportActionsProps {
  hasSelection: boolean;
  isOtherImportRunning: boolean;
  // Apply was clicked and the import is not sent yet (the pending save goes first): a second click must not send a second import
  isStarting: boolean;
  onStartOver: () => void;
  onApply: () => void;
}

const ConfigPresetImportActions: FunctionComponent<ConfigPresetImportActionsProps> = ({
  hasSelection,
  isOtherImportRunning,
  isStarting,
  onStartOver,
  onApply,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
      <Button variant="secondary" onClick={onStartOver}>{t_i18n('Start over')}</Button>
      <Button onClick={onApply} disabled={!hasSelection || isOtherImportRunning || isStarting}>{t_i18n('Apply')}</Button>
    </div>
  );
};

export default ConfigPresetImportActions;
