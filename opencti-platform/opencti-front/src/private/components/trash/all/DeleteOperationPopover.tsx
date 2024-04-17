import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import IconButton from '@mui/material/IconButton';
import DialogTitle from '@mui/material/DialogTitle';
import { DeleteOperationsLinesPaginationQuery$variables } from './__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import useDeletion from '../../../../utils/hooks/useDeletion';
import { RelayError } from '../../../../relay/relayTypes';
import { MESSAGING$ } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const DeleteOperationPopoverConfirmMutation = graphql`
  mutation DeleteOperationPopoverConfirmMutation($id: ID!) {
    deleteOperationConfirm(id: $id)
  }
`;

const DeleteOperationPopoverRestoreMutation = graphql`
  mutation DeleteOperationPopoverRestoreMutation($id: ID!) {
    deleteOperationRestore(id: $id)
  }
`;

interface DeleteOperationPopoverProps {
  mainEntityId: string;
  deletedCount: number;
  disabled?: boolean;
  paginationOptions: DeleteOperationsLinesPaginationQuery$variables;
}

const DeleteOperationPopover: React.FC<DeleteOperationPopoverProps> = ({ mainEntityId, deletedCount, disabled, paginationOptions }) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [commitConfirm] = useApiMutation(DeleteOperationPopoverConfirmMutation);
  const [commitRestore] = useApiMutation(DeleteOperationPopoverRestoreMutation);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(undefined);
  };

  const handleRestore = () => {
    // TODO: add confirm dialog, though a hook useConfirmDialog() that could replace also useDeletion
    commitRestore({
      variables: {
        id: mainEntityId,
      },
      onCompleted: () => {
        handleClose();
      },
    });
  };

  const {
    deleting,
    handleOpenDelete,
    displayDelete,
    handleCloseDelete,
    setDeleting,
  } = useDeletion({ handleClose });

  const submitDelete = () => {
    setDeleting(true);
    commitConfirm({
      variables: {
        id: mainEntityId,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_deleteOperations', paginationOptions, mainEntityId);
      },
    });
  };
  return (
    <>
      <IconButton
        color="primary"
        onClick={handleOpen}
        disabled={disabled}
        aria-haspopup="true"
        size="large"
      >
        <MoreVert fontSize="small" color="primary" />
      </IconButton>
      <Menu anchorEl={anchorEl} open={!!anchorEl} onClose={handleClose}>
        <MenuItem onClick={handleRestore}>{t_i18n('Restore')}</MenuItem>
        <MenuItem color="secondary" onClick={handleOpenDelete}>{t_i18n('Delete permanently')}</MenuItem>
      </Menu>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={displayDelete}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
        maxWidth="sm"
        fullWidth={true}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {t_i18n('', { id: 'The main object and the ... relationships/references linked to it will be deleted permanently.', values: { count: deletedCount - 1 } })}
          </DialogContentText>
          <DialogContentText>
            {t_i18n('This operation cannot be undone.')}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDelete} disabled={deleting}>
            {t_i18n('Cancel')}
          </Button>
          <Button color="secondary" onClick={submitDelete} disabled={deleting}>
            {t_i18n('Delete')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default DeleteOperationPopover;
