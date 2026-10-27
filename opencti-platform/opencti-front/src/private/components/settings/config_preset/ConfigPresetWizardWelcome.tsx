import React, { FunctionComponent } from 'react';
import { FileUploadOutlined, WidgetsOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Card from '@common/card/Card';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';

interface ConfigPresetWizardWelcomeProps {
  // Starts the import of a zip; the choice is disabled without it
  onImport?: () => void;
}

// The choices of the wizard: import a configuration bundle, or start from a template (coming later). There is no
// "start from scratch" choice: it is Skip.
const ConfigPresetWizardWelcome: FunctionComponent<ConfigPresetWizardWelcomeProps> = ({ onImport }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Text variant="content-base">
        {t_i18n('Start from a configuration you already have, or skip and configure everything yourself later. You can reopen this guide at any time from Settings › Experience.')}
      </Text>
      <div style={{ display: 'flex', gap: theme.spacing(2) }}>
        <div data-testid="config-preset-wizard-import" style={{ flex: 1 }}>
          <Card disabled={!onImport} onClick={onImport ?? (() => undefined)} aria-label={t_i18n('Import a configuration')}>
            <FileUploadOutlined />
            <Text variant="content-base">{t_i18n('Import a configuration')}</Text>
            <Text variant="content-base">{t_i18n('Upload a configuration bundle exported from another platform.')}</Text>
          </Card>
        </div>
        <div data-testid="config-preset-wizard-template" style={{ flex: 1 }}>
          <Card disabled onClick={() => undefined} aria-label={t_i18n('Start from a template')}>
            <WidgetsOutlined />
            <Text variant="content-base">{t_i18n('Start from a template')}</Text>
            <Text variant="content-base">{t_i18n('Coming later')}</Text>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default ConfigPresetWizardWelcome;
