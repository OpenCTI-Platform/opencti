import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { useFormatter } from '../../../../components/i18n';
import SubTypeWorkflowStatusEdit, { statusEditQuery } from './SubTypeWorkflowStatusEdit';
import Transition from '../../../../components/Transition';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowStatusEditQuery } from './__generated__/SubTypeWorkflowStatusEditQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const workflowStatusDeletionMutation = graphql`
  mutation SubTypeWorkflowStatusPopoverDeletionMutation(
    $id: ID!
    $statusId: String!
  ) {
    subTypeEdit(id: $id) {
      statusDelete(statusId: $statusId) {
        ...SubTypeWorkflow_subType
      }
    }
  }
`;

interface SubTypeStatusPopoverProps {
  subTypeId: string;
  statusId: string;
}

const SubTypeWorkflowStatusPopover: FunctionComponent<
SubTypeStatusPopoverProps
> = ({ subTypeId, statusId }) => {
  const { t_i18n } = useFormatter();
  const queryRef = useQueryLoading<SubTypeWorkflowStatusEditQuery>(
    statusEditQuery,
    { id: statusId },
  );
  const [anchorEl, setAnchorEl] = useState<HTMLElement | null>(null);
  const [displayUpdate, setDisplayUpdate] = useState<boolean>(false);
  const [displayDelete, setDisplayDelete] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const handleCloseUpdate = () => setDisplayUpdate(false);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const [commit] = useApiMutation(workflowStatusDeletionMutation);
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: {
        id: subTypeId,
        statusId,
      },
      onCompleted: () => {
        setDeleting(false);
        handleCloseDelete();
      },
    });
  };
  return (
    <>
      <IconButton onClick={handleOpen} aria-haspopup="true" size="large" color="primary">
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      {queryRef && (
        <React.Suspense fallback={<span />}>
          <SubTypeWorkflowStatusEdit
            subTypeId={subTypeId}
            queryRef={queryRef}
            open={displayUpdate}
            handleClose={handleCloseUpdate}
          />
        </React.Suspense>
      )}
      <Dialog
        open={displayDelete}
        slotProps={{ paper: { elevation: 1 } }}
        keepMounted={true}
        slots={{ transition: Transition }}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to remove this status?')}
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

export default SubTypeWorkflowStatusPopover;
