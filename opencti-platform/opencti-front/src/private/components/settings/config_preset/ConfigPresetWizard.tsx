import React, { FunctionComponent, ReactNode } from 'react';
import { graphql } from 'react-relay';
import { CloseOutlined, FileUploadOutlined, WidgetsOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/material/styles';
import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import Card from '@common/card/Card';
import { Text } from '@filigran/design-system';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const configPresetWizardSkipMutation = graphql`
  mutation ConfigPresetWizardSkipMutation($input: [EditInput]!) {
    meEdit(input: $input) {
      id
      bootstrap_wizard_skipped
    }
  }
`;

interface ConfigPresetWizardProps {
  // auto: opened by itself at the login, Skip is stored on the user. manual: opened from Settings, nothing is stored.
  mode: 'auto' | 'manual';
  onClose: () => void;
  // The current step, filled by the import steps; the welcome choices when absent
  children?: ReactNode;
}

const ConfigPresetWizardWelcome: FunctionComponent = () => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: theme.spacing(2) }}>
      <Text variant="content-base">
        {t_i18n('Start from a configuration you already have, or skip and configure everything yourself later. You can reopen this guide at any time from Settings › Experience.')}
      </Text>
      <div style={{ display: 'flex', gap: theme.spacing(2) }}>
        <div data-testid="config-preset-wizard-import" style={{ flex: 1 }}>
          <Card disabled onClick={() => undefined} aria-label={t_i18n('Import a configuration')}>
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

// Skip and X are the same: in auto mode the skip is stored on the user so that the wizard does not open by itself again.
// Clicking outside the dialog or pressing Escape does not close it: the dialog has no onClose.
const ConfigPresetWizard: FunctionComponent<ConfigPresetWizardProps> = ({ mode, onClose, children }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [commitSkip] = useApiMutation(configPresetWizardSkipMutation);
  const handleSkip = () => {
    if (mode === 'auto') {
      // The global error toast is the notification when the write fails: the dialog closes anyway
      commitSkip({ variables: { input: { key: 'bootstrap_wizard_skipped', value: [true] } }, onError: () => undefined });
    }
    onClose();
  };
  return (
    <Dialog
      open
      size="large"
      title={(
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>{t_i18n('Set up your platform')}</span>
          <IconButton aria-label={t_i18n('Close')} onClick={handleSkip}>
            <CloseOutlined fontSize="medium" />
          </IconButton>
        </div>
      )}
    >
      {children ?? <ConfigPresetWizardWelcome />}
      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: theme.spacing(3) }}>
        <Button variant="secondary" onClick={handleSkip}>
          {t_i18n('Skip')}
        </Button>
      </div>
    </Dialog>
  );
};

export default ConfigPresetWizard;
