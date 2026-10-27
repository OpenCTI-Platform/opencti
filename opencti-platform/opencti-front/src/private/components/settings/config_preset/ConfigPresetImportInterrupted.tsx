import React, { FunctionComponent, useState } from 'react';
import { Alert, Text } from '@filigran/design-system';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import ConfigPresetResultLine from './ConfigPresetResultLine';
import type { ConfigPresetImportSession } from './ConfigPresetImportWizard';

interface ConfigPresetImportInterruptedProps {
  session: ConfigPresetImportSession;
  onBackToSelection: () => void;
  onStartOver: () => void;
}

// The import stopped with its node: the items processed before the stop are kept in the session
const ConfigPresetImportInterrupted: FunctionComponent<ConfigPresetImportInterruptedProps> = ({ session, onBackToSelection, onStartOver }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [confirmStartOver, setConfirmStartOver] = useState(false);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(1.5) }}>
      <Alert severity="error" elevation={1} title={t_i18n('The import was interrupted')} description={t_i18n('The items processed before the stop are listed below. Going back to the selection keeps your selection.')} />
      {session.results.length > 0 && <Text variant="title-sm">{t_i18n('Items processed before the stop')}</Text>}
      {session.results.map((result) => (
        <ConfigPresetResultLine key={`${result.type}/${result.key}`} label={result.key} status={result.status} reason={result.reason} />
      ))}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1) }}>
        <Button variant="secondary" onClick={() => setConfirmStartOver(true)}>{t_i18n('Start over')}</Button>
        <Button onClick={onBackToSelection}>{t_i18n('Back to selection')}</Button>
      </div>
      <Dialog open={confirmStartOver} size="small" title={t_i18n('Start over')} onClose={() => setConfirmStartOver(false)}>
        <Text variant="content-base">{t_i18n('The uploaded bundle and your selection will be deleted.')}</Text>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: theme.spacing(1), marginTop: theme.spacing(3) }}>
          <Button variant="secondary" onClick={() => setConfirmStartOver(false)}>{t_i18n('Cancel')}</Button>
          <Button intent="destructive" onClick={onStartOver}>{t_i18n('Start over')}</Button>
        </div>
      </Dialog>
    </div>
  );
};

export default ConfigPresetImportInterrupted;
