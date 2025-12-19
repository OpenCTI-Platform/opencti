import React, { useState } from 'react';
import Alert from '@mui/material/Alert';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@common/button/Button';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import IconButton from '@common/button/IconButton';
import DialogTitle from '@mui/material/DialogTitle';
import { Link } from 'react-router-dom';
import { DeleteOperationsLinesPaginationQuery$variables } from './__generated__/DeleteOperationsLinesPaginationQuery.graphql';
import { DeleteOperationPopoverRestoreMutation, DeleteOperationPopoverRestoreMutation$data } from './__generated__/DeleteOperationPopoverRestoreMutation.graphql';
import { DeleteOperationPopoverConfirmMutation } from './__generated__/DeleteOperationPopoverConfirmMutation.graphql';
import { useFormatter } from '../../../../components/i18n';
import Transition from '../../../../components/Transition';
import { RelayError } from '../../../../relay/relayTypes';
import { MESSAGING$ } from '../../../../relay/environment';
import { deleteNode } from '../../../../utils/store';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const deleteOperationPopoverConfirmMutation = graphql`
  mutation DeleteOperationPopoverConfirmMutation($id: ID!) {
    deleteOperationConfirm(id: $id)
  }
`;

const deleteOperationPopoverRestoreMutation = graphql`
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
  const [deleting, setDeleting] = useState<boolean>(false);
  const [restoring, setRestoring] = useState<boolean>(false);
  const [displayConfirm, setDisplayConfirm] = useState<boolean>(false);
  const [confirmOperation, setConfirmOperation] = useState<string>('');

  const [commitConfirm] = useApiMutation<DeleteOperationPopoverConfirmMutation>(deleteOperationPopoverConfirmMutation);
  const [commitRestore] = useApiMutation<DeleteOperationPopoverRestoreMutation>(deleteOperationPopoverRestoreMutation);

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(undefined);
  };

  const handleOpenConfirm = () => {
    setDisplayConfirm(true);
    handleClose?.();
  };

  const handleCloseConfirm = () => {
    setDisplayConfirm(false);
  };

  const handleOpenRestore = () => {
    setConfirmOperation('restore');
    handleOpenConfirm();
  };

  const handleOpenDelete = () => {
    setConfirmOperation('delete');
    handleOpenConfirm();
  };

  const submitRestore = () => {
    setRestoring(true);
    commitRestore({
      variables: {
        id: mainEntityId,
      },
      onCompleted: (response: DeleteOperationPopoverRestoreMutation$data) => {
        const elementId = response.deleteOperationRestore;
        MESSAGING$.notifySuccess(<span><Link to={`/dashboard/id/${elementId}`}>{t_i18n('Object successfully restored')}</Link></span>);
        setRestoring(false);
        handleClose();
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
        setRestoring(false);
        handleCloseConfirm();
        handleClose();
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_deleteOperations', paginationOptions, mainEntityId);
      },
    });
  };

  const submitDelete = () => {
    setDeleting(true);
    commitConfirm({
      variables: {
        id: mainEntityId,
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Object permanently deleted'));
        setDeleting(false);
        handleClose();
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
        setDeleting(false);
        handleClose();
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_deleteOperations', paginationOptions, mainEntityId);
      },
    });
  };

  const submitConfirm = () => {
    if (confirmOperation === 'restore') {
      submitRestore();
    } else if (confirmOperation === 'delete') {
      submitDelete();
    }
  };

  return (
    <>
      <IconButton
        color="primary"
        onClick={handleOpen}
        disabled={disabled}
        aria-haspopup="true"
      >
        <MoreVert fontSize="small" color="primary" />
      </IconButton>
      <Menu anchorEl={anchorEl} open={!!anchorEl} onClose={handleClose}>
        <MenuItem onClick={handleOpenRestore}>{t_i18n('Restore')}</MenuItem>
        <MenuItem color="secondary" onClick={handleOpenDelete}>{t_i18n('Delete permanently')}</MenuItem>
      </Menu>

      <Dialog
        slotProps={{ paper: { elevation: 1 } }}
        open={displayConfirm}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseConfirm}
        maxWidth="sm"
        fullWidth={true}
      >
        <DialogTitle>
          {t_i18n('Are you sure?')}
        </DialogTitle>
        <DialogContent>
          <DialogContentText>
            {confirmOperation === 'delete' && (
              <Alert severity="warning" variant="outlined">
                {t_i18n('', { id: 'The main object and the ... relationships/references linked to it will be deleted permanently.', values: { count: deletedCount - 1 } })}
                <br />
                {t_i18n('This operation cannot be undone.')}
              </Alert>
            )}
            {confirmOperation === 'restore' && (
              t_i18n('', { id: 'The main object and the ... relationships/references linked to it will be restored.', values: { count: deletedCount - 1 } })
            )}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseConfirm} disabled={deleting || restoring}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitConfirm} disabled={deleting || restoring}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default DeleteOperationPopover;
