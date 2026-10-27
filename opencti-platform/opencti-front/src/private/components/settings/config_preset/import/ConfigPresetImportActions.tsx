import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import { useFormatter } from '../../../../../components/i18n';
import type { Theme } from '../../../../../components/Theme';

interface ConfigPresetImportActionsProps {
  hasSelection: boolean;
  isSimulating: boolean;
  isOtherImportRunning: boolean;
  onStartOver: () => void;
  onSimulate: () => void;
  onApply: () => void;
}

const ConfigPresetImportActions: FunctionComponent<ConfigPresetImportActionsProps> = ({
  hasSelection,
  isSimulating,
  isOtherImportRunning,
  onStartOver,
  onSimulate,
  onApply,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
      <Button variant="secondary" onClick={onStartOver} disabled={isSimulating}>{t_i18n('Start over')}</Button>
      <Button variant="secondary" onClick={onSimulate} disabled={!hasSelection || isSimulating}>{t_i18n('Simulate')}</Button>
      <Button onClick={onApply} disabled={!hasSelection || isSimulating || isOtherImportRunning}>{t_i18n('Apply')}</Button>
    </div>
  );
};

export default ConfigPresetImportActions;
