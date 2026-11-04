import React, { FunctionComponent, useState } from 'react';
import useAuth from '../../../../utils/hooks/useAuth';
import useGranted, { BYPASS } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import { RootSettings$data } from '../../../__generated__/RootSettings.graphql';
import ConfigPresetWizard from './ConfigPresetWizard';
import { shouldOpenConfigPresetWizard } from './configPresetWizardVisibility';

interface ConfigPresetBootstrapWizardProps {
  settings: RootSettings$data;
}

// Mounted once in the private app. Whether the wizard opens is decided at the first render, then the open state is local:
// the skip just written, or the status becoming completed, never closes it by itself.
const ConfigPresetBootstrapWizard: FunctionComponent<ConfigPresetBootstrapWizardProps> = ({ settings }) => {
  const { me } = useAuth();
  const { isFeatureEnable } = useHelper();
  const isBypass = useGranted([BYPASS]);
  const [open, setOpen] = useState(() => shouldOpenConfigPresetWizard({
    isBypass,
    isFeatureEnabled: isFeatureEnable('CONFIG_PRESET'),
    isOptionEnabled: settings.platform_bootstrap_wizard_enabled,
    status: settings.platform_bootstrap_status,
    isSkipped: me?.bootstrap_wizard_skipped,
  }));
  return open ? <ConfigPresetWizard mode="auto" onClose={() => setOpen(false)} /> : null;
};

export default ConfigPresetBootstrapWizard;
