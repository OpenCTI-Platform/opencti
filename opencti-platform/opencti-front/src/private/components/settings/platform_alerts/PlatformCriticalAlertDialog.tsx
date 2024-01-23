import React, { useState } from 'react';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogTitle from '@mui/material/DialogTitle';

import UserWithNullEffectiveConfidenceLevelAlertContent from '@components/settings/platform_alerts/UserWithNullEffectiveConfidenceLevelAlertContent';
import { useFormatter } from '../../../../components/i18n';
import { RootSettings$data } from '../../../__generated__/RootSettings.graphql';
import Transition from '../../../../components/Transition';
import useGranted, { SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';

type PlatformCriticalAlertDialogProps = {
  alerts: RootSettings$data['platform_critical_alerts']
};

const PlatformCriticalAlertDialog: React.FC<PlatformCriticalAlertDialogProps> = ({ alerts }) => {
  const { t_i18n } = useFormatter();
  const hasSetAccesses = useGranted([SETTINGS_SETACCESSES]);

  const [open, setOpen] = useState<boolean>(alerts.length > 0);

  // we only display the first alert if any.
  const alert = alerts[0];

  if (!alert || !hasSetAccesses) {
    return null;
  }

  const closeHandler = () => {
    setOpen(false);
  };

  const getDialogContentFromAlertType = () => {
    switch (alert.type) {
      case 'USER_WITH_NULL_EFFECTIVE_LEVEL': {
        return <UserWithNullEffectiveConfidenceLevelAlertContent alert={alert} closeHandler={closeHandler} />;
      }
      default:
        return <DialogContent>{t_i18n('Unknown configuration error in the platform.')}</DialogContent>;
    }
  };

  return (
    <Dialog
      open={open}
      PaperProps={{ elevation: 1 }}
      TransitionComponent={Transition}
      onClose={closeHandler}
    >
      <DialogTitle>{t_i18n('Important notice: your action is required!')}</DialogTitle>
      {getDialogContentFromAlertType()}
    </Dialog>
  );
};

export default PlatformCriticalAlertDialog;
