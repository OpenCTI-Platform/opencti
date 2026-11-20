import React, { FunctionComponent, ReactNode } from 'react';
import { graphql } from 'react-relay';
import { CloseOutlined } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import ConfigPresetImportWizard from './import/ConfigPresetImportWizard';

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
  // The current step; the import wizard when absent
  children?: ReactNode;
}

// Skip and X are the same: in auto mode the skip is stored on the user so that the wizard does not open by itself again.
// Clicking outside the dialog or pressing Escape does not close it: the dialog has no onClose.
const ConfigPresetWizard: FunctionComponent<ConfigPresetWizardProps> = ({ mode, onClose, children }) => {
  const { t_i18n } = useFormatter();
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
          <span>{t_i18n('Quick Start - Platform Setup')}</span>
          <IconButton aria-label={t_i18n('Close')} onClick={handleSkip}>
            <CloseOutlined fontSize="medium" />
          </IconButton>
        </div>
      )}
    >
      {children ?? <ConfigPresetImportWizard onFinish={onClose} />}
    </Dialog>
  );
};

export default ConfigPresetWizard;
