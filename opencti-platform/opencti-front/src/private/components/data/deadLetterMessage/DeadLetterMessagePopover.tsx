import React, { useState } from 'react';
import { graphql } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import DialogActions from '@mui/material/DialogActions';
import DialogContentText from '@mui/material/DialogContentText';
import IconButton from '@common/button/IconButton';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import { useFormatter } from '../../../../components/i18n';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import { MESSAGING$ } from '../../../../relay/environment';
import { RelayError } from '../../../../relay/relayTypes';
import { deleteNode } from '../../../../utils/store';
import { DeadLetterMessagePopoverDeleteMutation } from './__generated__/DeadLetterMessagePopoverDeleteMutation.graphql';
import { DeadLetterMessagePopoverRetryMutation } from './__generated__/DeadLetterMessagePopoverRetryMutation.graphql';
import { DeadLetterMessagesLinesPaginationQuery$variables } from '../__generated__/DeadLetterMessagesLinesPaginationQuery.graphql';

const deadLetterMessagePopoverDeleteMutation = graphql`
  mutation DeadLetterMessagePopoverDeleteMutation($id: String!) {
    deadLetterMessageDelete(id: $id)
  }
`;

const deadLetterMessagePopoverRetryMutation = graphql`
  mutation DeadLetterMessagePopoverRetryMutation($id: String!) {
    deadLetterMessageRetry(id: $id)
  }
`;

interface DeadLetterMessagePopoverProps {
  messageId: string;
  paginationOptions: DeadLetterMessagesLinesPaginationQuery$variables;
}

const DeadLetterMessagePopover: React.FC<DeadLetterMessagePopoverProps> = ({
  messageId,
  paginationOptions,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [displayConfirm, setDisplayConfirm] = useState(false);
  const [confirmOperation, setConfirmOperation] = useState<'delete' | 'retry'>('delete');
  const [processing, setProcessing] = useState(false);

  const [commitDelete] = useApiMutation<DeadLetterMessagePopoverDeleteMutation>(
    deadLetterMessagePopoverDeleteMutation,
  );
  const [commitRetry] = useApiMutation<DeadLetterMessagePopoverRetryMutation>(
    deadLetterMessagePopoverRetryMutation,
  );

  const handleOpen = (event: React.SyntheticEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(undefined);
  };

  const handleOpenConfirm = (operation: 'delete' | 'retry') => {
    setConfirmOperation(operation);
    setDisplayConfirm(true);
    handleClose();
  };

  const handleCloseConfirm = () => {
    setDisplayConfirm(false);
  };

  const submitDelete = () => {
    setProcessing(true);
    commitDelete({
      variables: { id: messageId },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Dead letter message deleted'));
        setProcessing(false);
        handleCloseConfirm();
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
        setProcessing(false);
        handleCloseConfirm();
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_deadLetterMessages', paginationOptions, messageId);
      },
    });
  };

  const submitRetry = () => {
    setProcessing(true);
    commitRetry({
      variables: { id: messageId },
      onCompleted: () => {
        MESSAGING$.notifySuccess(t_i18n('Dead letter message sent for retry'));
        setProcessing(false);
        handleCloseConfirm();
      },
      onError: (error) => {
        const { errors } = (error as unknown as RelayError).res;
        MESSAGING$.notifyError(errors.at(0)?.message);
        setProcessing(false);
        handleCloseConfirm();
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_deadLetterMessages', paginationOptions, messageId);
      },
    });
  };

  const submitConfirm = () => {
    if (confirmOperation === 'delete') {
      submitDelete();
    } else {
      submitRetry();
    }
  };

  return (
    <>
      <IconButton
        color="primary"
        onClick={handleOpen}
        aria-haspopup="true"
      >
        <MoreVert fontSize="small" color="primary" />
      </IconButton>
      <Menu anchorEl={anchorEl} open={!!anchorEl} onClose={handleClose}>
        <MenuItem onClick={() => handleOpenConfirm('retry')}>{t_i18n('Retry')}</MenuItem>
        <MenuItem onClick={() => handleOpenConfirm('delete')}>{t_i18n('Delete')}</MenuItem>
      </Menu>

      <Dialog
        open={displayConfirm}
        onClose={handleCloseConfirm}
        title={t_i18n('Are you sure?')}
      >
        <DialogContentText>
          {confirmOperation === 'delete'
            ? t_i18n('This dead letter message will be permanently deleted.')
            : t_i18n('This dead letter message will be sent back to its original connector queue for retry.')}
        </DialogContentText>
        <DialogActions>
          <Button variant="secondary" onClick={handleCloseConfirm} disabled={processing}>
            {t_i18n('Cancel')}
          </Button>
          <Button onClick={submitConfirm} disabled={processing}>
            {t_i18n('Confirm')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

export default DeadLetterMessagePopover;