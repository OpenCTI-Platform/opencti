import React from 'react';
import { SettingsMessagesLine_settingsMessage$data } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import SettingsMessageForm from './SettingsMessageForm';

const SettingsMessageEdition = ({
  settingsId,
  message,
  handleClose,
}: {
  settingsId: string
  message: SettingsMessagesLine_settingsMessage$data
  handleClose: () => void
}) => {
  return (
    <SettingsMessageForm
      settingsId={settingsId}
      message={message}
      handleClose={handleClose}
    />
  );
};

export default SettingsMessageEdition;
