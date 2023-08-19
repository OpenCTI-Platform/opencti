import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import React, { useState } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import { graphql, useMutation } from 'react-relay';
import SettingsMessageEdition from './SettingsMessageEdition';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { SettingsMessagesLine_settingsMessage$data } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';

const settingsMessagesPopoverPatch = graphql`
  mutation SettingsMessagesPopoverPatchMutation(
    $id: ID!
    $input: String!
  ) {
    settingsEdit(id: $id) {
      deleteMessage(input: $input) {
        platform_messages {
          ...SettingsMessagesLine_settingsMessage
        }
      }
    }
  }
`;

const SettingsMessagesPopover = ({
  settingsId,
  message,
}: {
  settingsId: string
  message: SettingsMessagesLine_settingsMessage$data
}) => {
  const { t } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const handleOpen = (event: React.MouseEvent) => setAnchorEl(event.currentTarget);
  const handleClose = () => {
    setAnchorEl(null);
  };
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const handleCloseUpdate = () => setDisplayUpdate(false);

  const deletion = useDeletion({ handleClose });

  const [commit] = useMutation(settingsMessagesPopoverPatch);
  const submitDelete = () => {
    deletion.setDeleting(true);
    commit({
      variables: {
        id: settingsId,
        input: message.id,
      },
      onCompleted: () => {
        deletion.setDeleting(false);
        handleClose();
      },
    });
  };

  return (
    <div>
      <IconButton onClick={handleOpen} aria-haspopup="true" size="large">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t('Update')}</MenuItem>
        <MenuItem onClick={deletion.handleOpenDelete}>{t('Delete')}</MenuItem>
      </Menu>
      <SettingsMessageEdition
        settingsId={settingsId}
        message={message}
        handleClose={handleCloseUpdate}
        open={displayUpdate}
      />
      <DeleteDialog
        title={t('Do you want to delete this message ?')}
        deletion={deletion}
        submitDelete={submitDelete}
      />
    </div>
  );
};

export default SettingsMessagesPopover;
