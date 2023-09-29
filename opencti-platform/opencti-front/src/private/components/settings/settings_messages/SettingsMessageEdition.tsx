import React from 'react';
import { SettingsMessagesLine_settingsMessage$data } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import SettingsMessageForm from './SettingsMessageForm';

const SettingsMessageEdition = ({
  settingsId,
  message,
  handleClose,
  open,
}: {
  settingsId: string
  message: SettingsMessagesLine_settingsMessage$data
  handleClose: () => void
  open?: boolean
}) => {
  return (
    <SettingsMessageForm
      settingsId={settingsId}
      message={message}
      handleClose={handleClose}
      open={open}
    />
  );
};

export default SettingsMessageEdition;
