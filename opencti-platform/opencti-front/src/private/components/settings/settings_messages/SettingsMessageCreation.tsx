import React from 'react';
import SettingsMessageForm from './SettingsMessageForm';

const SettingsMessageCreation = ({
  settingsId,
  handleClose,
}: {
  settingsId: string;
  handleClose: () => void;
}) => {
  return (
    <SettingsMessageForm
      settingsId={settingsId}
      handleClose={handleClose}
      creation={true}
    />
  );
};

export default SettingsMessageCreation;
