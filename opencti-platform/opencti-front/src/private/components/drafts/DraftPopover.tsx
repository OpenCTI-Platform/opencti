import React, { UIEvent, useState } from 'react';
import MoreVert from '@mui/icons-material/MoreVert';
import IconButton from '@mui/material/IconButton';
import MenuItem from '@mui/material/MenuItem';
import Menu from '@mui/material/Menu';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Dialog from '@mui/material/Dialog';
import { graphql } from 'react-relay';
import { PopoverProps } from '@mui/material/Popover';
import { DraftsLinesPaginationQuery$variables } from '@components/drafts/__generated__/DraftsLinesPaginationQuery.graphql';
import { DraftPopoverDeleteMutation } from '@components/drafts/__generated__/DraftPopoverDeleteMutation.graphql';
import { draftContextBannerMutation } from '@components/drafts/DraftContextBanner';
import { DraftContextBannerMutation, DraftContextBannerMutation$data } from '@components/drafts/__generated__/DraftContextBannerMutation.graphql';
import DialogTitle from '@mui/material/DialogTitle';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import Transition from '../../../components/Transition';
import { KNOWLEDGE } from '../../../utils/hooks/useGranted';
import Security from '../../../utils/Security';
import { useFormatter } from '../../../components/i18n';
import { MESSAGING$ } from '../../../relay/environment';
import { deleteNode } from '../../../utils/store';
import { RelayError } from '../../../relay/relayTypes';
import stopEvent from '../../../utils/domEvent';

const draftPopoverDeleteMutation = graphql`
    mutation DraftPopoverDeleteMutation($id: ID!) {
        draftWorkspaceDelete(id: $id)
    }
`;

interface DraftPopoverProps {
  draftId: string;
  paginationOptions: DraftsLinesPaginationQuery$variables;
  updater?: (
    store: RecordSourceSelectorProxy<DraftContextBannerMutation$data>,
  ) => void;
}

const DraftPopover: React.FC<DraftPopoverProps> = ({
  draftId,
  paginationOptions,
  updater,
}) => {
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>();
  const [openSwitch, setOpenSwitch] = useState(false);
  const [openDelete, setOpenDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [switchToDraft, setSwitchToDraft] = useState(false);
  const [commitSwitchToDraft] = useApiMutation<DraftContextBannerMutation>(draftContextBannerMutation);
  const deleteSuccessMessage = t_i18n('', {
    id: '... successfully deleted',
    values: { entity_type: t_i18n('entity_DraftWorkspace') },
  });
  const [commitDeletion] = useApiMutation<DraftPopoverDeleteMutation>(
    draftPopoverDeleteMutation,
    undefined,
    { successMessage: deleteSuccessMessage },
  );
  const handleOpen = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };
  const handleClose = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const handleOpenSwitch = (event: UIEvent) => {
    setOpenSwitch(true);
    handleClose(event);
  };

  const handleCloseSwitch = (event: UIEvent) => {
    stopEvent(event);
    setOpenSwitch(false);
  };

  const handleOpenDelete = (event: UIEvent) => {
    setOpenDelete(true);
    handleClose(event);
  };

  const handleCloseDelete = (event: UIEvent) => {
    stopEvent(event);
    setOpenDelete(false);
  };

  const submitDelete = (event: UIEvent) => {
    stopEvent(event);
    setDeleting(true);
    commitDeletion({
      variables: {
        id: draftId,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose(event);
        handleCloseDelete(event);
      },
      onError: (error) => {
        MESSAGING$.notifyRelayError(error as unknown as RelayError);
        setDeleting(false);
        handleClose(event);
        handleCloseDelete(event);
      },
      updater: (store) => {
        deleteNode(store, 'Pagination_draftWorkspaces', paginationOptions, draftId);
      },
    });
  };

  const submitToDraft = (event: UIEvent) => {
    stopEvent(event);
    setSwitchToDraft(true);
    commitSwitchToDraft({
      variables: {
        input: [{ key: 'draft_context', value: [draftId] }],
      },
      onCompleted: () => {
        MESSAGING$.notifySuccess(<span>{t_i18n('You are now in Draft Mode')}</span>);
        setSwitchToDraft(false);
        handleClose(event);
        handleCloseSwitch(event);
      },
      onError: (error) => {
        MESSAGING$.notifyRelayError(error as unknown as RelayError);
        setSwitchToDraft(false);
        handleClose(event);
        handleCloseSwitch(event);
      },
      updater: (store) => updater && updater(store),
    });
  };

  return (
    <Security needs={[KNOWLEDGE]}>
      <div>
        <IconButton
          onClick={handleOpen}
          aria-haspopup="true"
          size="large"
          color="primary"
          aria-label={t_i18n('Draft popover of actions')}
        >
          <MoreVert fontSize="small" />
        </IconButton>
        <Menu
          anchorEl={anchorEl}
          open={Boolean(anchorEl)}
          onClose={handleClose}
        >
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          <MenuItem onClick={handleOpenSwitch}>{t_i18n('Switch to Draft')}</MenuItem>
        </Menu>
        <Dialog
          open={openDelete}
          PaperProps={{ elevation: 1 }}
          keepMounted={true}
          TransitionComponent={Transition}
          onClose={handleCloseDelete}
        >
          <DialogContent>
            <DialogContentText>
              {t_i18n('Do you want to delete this draft?')}
            </DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseDelete} disabled={deleting}>{t_i18n('Cancel')}</Button>
            <Button onClick={submitDelete} disabled={deleting} color="secondary">
              {t_i18n('Delete')}
            </Button>
          </DialogActions>
        </Dialog>
        <Dialog
          open={openSwitch}
          PaperProps={{ elevation: 1 }}
          TransitionComponent={Transition}
          onClose={handleCloseSwitch}
          fullWidth={true}
          maxWidth="xs"
        >
          <DialogTitle>{t_i18n('Switch to Draft Mode')}</DialogTitle>
          <DialogContent>
            <DialogContentText>{t_i18n('You are about to switch to Draft mode. All your OpenCTI Plateform will be in draft. The selected Draft will be the draft by default.')}</DialogContentText>
          </DialogContent>
          <DialogActions>
            <Button onClick={handleCloseSwitch}>{t_i18n('Cancel')}</Button>
            <Button
              color="secondary"
              onClick={submitToDraft}
              disabled={switchToDraft}
            >
              {t_i18n('Switch to Draft')}
            </Button>
          </DialogActions>
        </Dialog>
      </div>
    </Security>

  );
};

export default DraftPopover;
