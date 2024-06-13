import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import Button from '@mui/material/Button';
import IconButton from '@mui/material/IconButton';
import Dialog from '@mui/material/Dialog';
import DialogActions from '@mui/material/DialogActions';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import MoreVert from '@mui/icons-material/MoreVert';
import { graphql } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import PropTypes from 'prop-types';
import { useNavigate } from 'react-router-dom';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkspaceEditionContainer from './WorkspaceEditionContainer';
import Security from '../../../utils/Security';
import { EXPLORE_EXUPDATE_EXDELETE } from '../../../utils/hooks/useGranted';
import Transition from '../../../components/Transition';
import { deleteNode, insertNode } from '../../../utils/store';
import handleExportJson from './workspaceExportHandler';
import WorkspaceDuplicationDialog from './WorkspaceDuplicationDialog';
import useApiMutation from '../../../utils/hooks/useApiMutation';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
  },
}));

const workspaceEditionQuery = graphql`
  query WorkspacePopoverContainerQuery($id: String!) {
    workspace(id: $id) {
      ...WorkspaceEditionContainer_workspace
    }
  }
`;

const WorkspacePopoverDeletionMutation = graphql`
  mutation WorkspacePopoverDeletionMutation($id: ID!) {
    workspaceDelete(id: $id)
  }
`;

const WorkspacePopover = ({ workspace, paginationOptions }) => {
  const { id, type } = workspace;
  const navigate = useNavigate();
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = useState(null);
  const [displayDelete, setDisplayDelete] = useState(false);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [duplicating, setDuplicating] = useState(false);
  const handleOpen = (event) => setAnchorEl(event.currentTarget);
  const handleClose = () => setAnchorEl(null);
  const handleOpenDelete = () => {
    setDisplayDelete(true);
    handleClose();
  };
  const handleCloseDelete = () => setDisplayDelete(false);
  const handleCloseDuplicate = () => {
    setDisplayDuplicate(false);
  };
  const [commit] = useApiMutation(WorkspacePopoverDeletionMutation);
  const updater = (store) => {
    if (paginationOptions) {
      insertNode(store, 'Pagination_workspaces', paginationOptions, 'workspaceDuplicate');
    }
  };
  const submitDelete = () => {
    setDeleting(true);
    commit({
      variables: { id },
      updater: (store) => {
        if (paginationOptions) {
          deleteNode(store, 'Pagination_workspaces', paginationOptions, id);
        }
      },
      onCompleted: () => {
        setDeleting(false);
        handleClose();
        if (paginationOptions) {
          handleCloseDelete();
        } else {
          navigate(`/dashboard/workspaces/${type}s`);
        }
      },
    });
  };

  const handleOpenEdit = () => {
    setDisplayEdit(true);
    handleClose();
  };
  const handleDashboardDuplication = () => {
    setDisplayDuplicate(true);
    handleClose();
  };

  const handleCloseEdit = () => setDisplayEdit(false);
  const userCanManage = workspace.currentUserAccessRight === 'admin';
  const userCanEdit = userCanManage || workspace.currentUserAccessRight === 'edit';
  if (!userCanEdit) {
    return <></>;
  }
  return (
    <div className={classes.container}>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="large"
        style={{ marginTop: 3 }}
        color="primary"
        aria-label={t_i18n('Workspace popover of actions')}
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose} aria-label="Workspace menu">
        <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        {workspace.type === 'dashboard' && [
          <MenuItem key="menu_duplicate" onClick={handleDashboardDuplication}>{t_i18n('Duplicate')}</MenuItem>,
          <MenuItem key="menu_export" onClick={() => handleExportJson(workspace)}>{t_i18n('Export')}</MenuItem>,
        ]}
        <Security needs={[EXPLORE_EXUPDATE_EXDELETE]} hasAccess={userCanManage}>
          <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>
      <WorkspaceDuplicationDialog
        workspace={workspace}
        displayDuplicate={displayDuplicate}
        handleCloseDuplicate={handleCloseDuplicate}
        duplicating={duplicating}
        setDuplicating={setDuplicating}
        updater={updater}
        paginationOptions={paginationOptions}
      />
      <Dialog
        open={displayDelete}
        PaperProps={{ elevation: 1 }}
        keepMounted={true}
        TransitionComponent={Transition}
        onClose={handleCloseDelete}
      >
        <DialogContent>
          <DialogContentText>
            {t_i18n('Do you want to delete this workspace?')}
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
      <QueryRenderer
        query={workspaceEditionQuery}
        variables={{ id }}
        render={({ props: editionProps }) => {
          if (!editionProps) {
            return <div />;
          }
          return (
            <WorkspaceEditionContainer
              workspace={editionProps.workspace}
              handleClose={handleCloseEdit}
              open={displayEdit}
              type={type}
            />
          );
        }}
      />
    </div>
  );
};

WorkspacePopover.propTypes = {
  workspace: PropTypes.object,
  paginationOptions: PropTypes.object,
};

export default WorkspacePopover;
