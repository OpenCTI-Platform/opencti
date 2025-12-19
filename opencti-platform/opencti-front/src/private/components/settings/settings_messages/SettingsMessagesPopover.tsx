import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import React, { useState } from 'react';
import { PopoverProps } from '@mui/material/Popover';
import { graphql } from 'react-relay';
import SettingsMessageEdition from './SettingsMessageEdition';
import { useFormatter } from '../../../../components/i18n';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { SettingsMessagesLine_settingsMessage$data } from './__generated__/SettingsMessagesLine_settingsMessage.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const settingsMessagesPopoverPatch = graphql`
  mutation SettingsMessagesPopoverPatchMutation(
    $id: ID!
    $input: String!
  ) {
    settingsEdit(id: $id) {
      deleteMessage(input: $input) {
        messages_administration {
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
  settingsId: string;
  message: SettingsMessagesLine_settingsMessage$data;
}) => {
  const { t_i18n } = useFormatter();

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

  const [commit] = useApiMutation(settingsMessagesPopoverPatch);
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: settingsId,
        input: message.id,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
      },
    });
  };

  return (
    <div>
      <IconButton onClick={handleOpen} aria-haspopup="true" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <SettingsMessageEdition
        settingsId={settingsId}
        message={message}
        handleClose={handleCloseUpdate}
        open={displayUpdate}
      />
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this message?')}
      />
    </div>
  );
};

export default SettingsMessagesPopover;
