import Button from '@common/button/Button';
import IconButton from '@common/button/IconButton';
import Dialog from '@common/dialog/Dialog';
import { TrashDeleteOperationsLinesPaginationQuery$variables } from '@components/trash/__generated__/TrashDeleteOperationsLinesPaginationQuery.graphql';
import MoreVert from '@mui/icons-material/MoreVert';
import Alert from '@mui/material/Alert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import { PopoverProps } from '@mui/material/Popover';
import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { Link } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import { RelayError } from '../../../relay/relayTypes';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { deleteNode } from '../../../utils/store';
import { DeleteOperationPopoverConfirmMutation } from './__generated__/DeleteOperationPopoverConfirmMutation.graphql';
import { DeleteOperationPopoverRestoreMutation, DeleteOperationPopoverRestoreMutation$data } from './__generated__/DeleteOperationPopoverRestoreMutation.graphql';

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
  paginationOptions: TrashDeleteOperationsLinesPaginationQuery$variables;
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
        open={displayConfirm}
        onClose={handleCloseConfirm}
        title={t_i18n('Are you sure?')}
      >
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
