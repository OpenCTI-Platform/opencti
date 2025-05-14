import React, { useState } from 'react';
import { graphql } from 'react-relay';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@mui/material/IconButton';
import MoreVert from '@mui/icons-material/MoreVert';
import makeStyles from '@mui/styles/makeStyles';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../../components/i18n';
import GroupEdition from './GroupEdition';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import DeleteDialog from '../../../../components/DeleteDialog';
import useDeletion from '../../../../utils/hooks/useDeletion';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const groupPopoverCleanContext = graphql`
  mutation GroupPopoverCleanContextMutation($id: ID!) {
    groupEdit(id: $id) {
      contextClean {
        ...GroupEditionContainer_group
      }
    }
  }
`;

const groupPopoverDeletionMutation = graphql`
  mutation GroupPopoverDeletionMutation($id: ID!) {
    groupEdit(id: $id) {
      delete
    }
  }
`;

const GroupPopover = ({ groupId, disabled = false }: { groupId: string, disabled?: boolean }) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const navigate = useNavigate();
  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayUpdate, setDisplayUpdate] = useState(false);
  const [commitCleanContext] = useApiMutation(groupPopoverCleanContext);
  const [commitDeleteMutation] = useApiMutation(groupPopoverDeletionMutation);

  const handleOpen = (event: React.MouseEvent) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const handleOpenUpdate = () => {
    setDisplayUpdate(true);
    handleClose();
  };

  const handleCloseUpdate = () => {
    commitCleanContext({
      variables: { id: groupId },
    });
    setDisplayUpdate(false);
  };

  const deletion = useDeletion({ handleClose });
  const { setDeleting, handleOpenDelete } = deletion;
  const submitDelete = () => {
    setDeleting(true);
    commitDeleteMutation({
      variables: {
        id: groupId,
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        navigate('/dashboard/settings/accesses/groups');
      },
    });
  };

  return (
    <div className={classes.container}>
      <IconButton
        onClick={(event) => handleOpen(event)}
        aria-haspopup="true"
        size="large"
        style={{ marginTop: 3 }}
        disabled={disabled}
        color={'primary'}
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
        <MenuItem onClick={handleOpenUpdate}>{t_i18n('Update')}</MenuItem>
        <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
      </Menu>
      <GroupEdition groupId={groupId} handleClose={handleCloseUpdate} open={displayUpdate} />
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={t_i18n('Do you want to delete this group?')}
      />
    </div>
  );
};

export default GroupPopover;
