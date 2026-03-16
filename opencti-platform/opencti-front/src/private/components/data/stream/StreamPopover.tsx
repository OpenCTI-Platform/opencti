import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import OpenInNewOutlined from '@mui/icons-material/OpenInNewOutlined';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@common/button/IconButton';
import { PopoverProps } from '@mui/material/Popover';
import { StreamLine_node$data } from './__generated__/StreamLine_node.graphql';
import { useFormatter } from '../../../../components/i18n';
import { APP_BASE_PATH } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { deleteNode } from '../../../../utils/store';
import Drawer from '../../common/drawer/Drawer';
import Security from '../../../../utils/Security';
import StreamCollectionEdition, { streamCollectionMutationFieldPatch } from './StreamCollectionEdition';
import DeleteDialog from '../../../../components/DeleteDialog';
import { TAXIIAPI_SETCOLLECTIONS } from '../../../../utils/hooks/useGranted';

const streamCollectionPopoverDeletionMutation = graphql`
  mutation StreamPopoverDeletionMutation($id: ID!) {
    streamCollectionEdit(id: $id) {
      delete
    }
  }
`;

interface StreamCollectionPopoverProps {
  streamCollection: StreamLine_node$data;
  paginationOptions: Record<string, unknown>;
}

const StreamCollectionPopover: FunctionComponent<StreamCollectionPopoverProps> = ({
  streamCollection,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();

  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);

  const [commitDelete] = useApiMutation(streamCollectionPopoverDeletionMutation);
  const [commitFieldPatch] = useApiMutation(streamCollectionMutationFieldPatch);

  // Popover
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => setAnchorEl(null);

  // Update
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const handleCloseUpdate = () => setDisplayUpdate(false);

  // Delete
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;

  const submitDelete = () => {
    setDeleting(true);
    commitDelete({
      variables: { id: streamCollection.id },
      updater: (store) => {
        deleteNode(
          store,
          'Pagination_streamCollections',
          paginationOptions,
          streamCollection.id,
        );
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };

  // Open stream
  const handleOpenStream = () => {
    handleClose();
    window.open(`${APP_BASE_PATH}/stream/${streamCollection.id}`, '_blank');
  };

  // Start/Stop
  const handleOnOff = () => {
    handleClose();
    commitFieldPatch({
      variables: {
        id: streamCollection.id,
        input: [
          {
            key: 'stream_live',
            value: [(!streamCollection.stream_live).toString()],
          },
        ],
      },
    });
  };

  return (
    <div style={{ margin: 0 }}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        style={{ marginTop: 3 }}
        color="primary"
      >
        <MoreVert />
      </IconButton>
      <Menu
        anchorEl={anchorEl}
        open={Boolean(anchorEl)}
        onClose={handleClose}
      >
        <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
          <>
            <MenuItem onClick={handleOnOff}>
              {t_i18n(streamCollection.stream_live ? 'Stop' : 'Start')}
            </MenuItem>
            <MenuItem onClick={handleOpenUpdate}>
              {t_i18n('Update')}
            </MenuItem>
            <MenuItem onClick={handleOpenDelete}>
              {t_i18n('Delete')}
            </MenuItem>
          </>
        </Security>
        <MenuItem onClick={handleOpenStream} disabled={!streamCollection.stream_live}>
          <ListItemIcon>
            <OpenInNewOutlined fontSize="small" />
          </ListItemIcon>
          <ListItemText>{t_i18n('Open stream')}</ListItemText>
        </MenuItem>
      </Menu>
      <Security needs={[TAXIIAPI_SETCOLLECTIONS]}>
        <>
          <Drawer
            open={displayUpdate}
            title={t_i18n('Update a live stream')}
            onClose={handleCloseUpdate}
          >
            <StreamCollectionEdition
              streamCollection={streamCollection}
            />
          </Drawer>
          <DeleteDialog
            deletion={deletion}
            submitDelete={submitDelete}
            message={t_i18n('Do you want to delete this live stream?')}
          />
        </>
      </Security>
    </div>
  );
};

export default StreamCollectionPopover;
