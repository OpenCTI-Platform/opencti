import React from 'react';
import SettingsMessageForm from './SettingsMessageForm';

const SettingsMessageCreation = ({
  settingsId,
  handleClose,
  open,
}: {
  settingsId: string
  handleClose: () => void
  open?: boolean
}) => {
  return (
    <SettingsMessageForm
      settingsId={settingsId}
      handleClose={handleClose}
      creation
      open={open}
    />
  );
};

export default SettingsMessageCreation;
