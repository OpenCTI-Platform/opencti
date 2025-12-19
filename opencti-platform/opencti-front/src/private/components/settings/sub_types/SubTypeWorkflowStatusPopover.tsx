import React, { FunctionComponent, useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import { useFormatter } from '../../../../components/i18n';
import SubTypeWorkflowStatusEdit, { statusEditQuery } from './SubTypeWorkflowStatusEdit';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { SubTypeWorkflowStatusEditQuery } from './__generated__/SubTypeWorkflowStatusEditQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

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
  const handleOpen = (event: React.MouseEvent<HTMLElement>) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };
  const handleCloseUpdate = () => setDisplayUpdate(false);
  const [commit] = useApiMutation(workflowStatusDeletionMutation);
  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;
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
      <IconButton onClick={handleOpen} aria-haspopup="true" color="primary">
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
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this status?')}
      />
    </>
  );
};

export default SubTypeWorkflowStatusPopover;
