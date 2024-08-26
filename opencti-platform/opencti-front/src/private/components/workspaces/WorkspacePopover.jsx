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
import PublicDashboardCreationForm from './dashboards/public_dashboards/PublicDashboardCreationForm';
import Drawer from '../common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import { QueryRenderer } from '../../../relay/environment';
import WorkspaceEditionContainer from './WorkspaceEditionContainer';
import Security from '../../../utils/Security';
import { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_EXDELETE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE_INDELETE } from '../../../utils/hooks/useGranted';
import Transition from '../../../components/Transition';
import { deleteNode, insertNode } from '../../../utils/store';
import handleExportJson from './workspaceExportHandler';
import WorkspaceDuplicationDialog from './WorkspaceDuplicationDialog';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { getCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import useHelper from '../../../utils/hooks/useHelper';

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
  const { isFeatureEnable } = useHelper();

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
  const { canManage, canEdit } = getCurrentUserAccessRight(workspace.currentUserAccessRight);
  if (!canEdit && workspace.type !== 'dashboard') {
    return <></>;
  }

  const goToPublicDashboards = () => {
    const filter = {
      mode: 'and',
      filterGroups: [],
      filters: [{
        key: 'dashboard_id',
        values: [workspace.id],
        mode: 'or',
        operator: 'eq',
      }],
    };
    navigate(`/dashboard/workspaces/dashboards_public?filters=${JSON.stringify(filter)}`);
  };

  // -- Creation public dashboard --
  const [displayCreate, setDisplayCreate] = useState(false);

  const handleOpenCreation = () => {
    setDisplayCreate(true);
    handleClose();
  };
  const handleCloseCreate = () => setDisplayCreate(false);

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
        <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        </Security>
        {workspace.type === 'dashboard' && (
          <>
            <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
              <MenuItem onClick={handleDashboardDuplication}>{t_i18n('Duplicate')}</MenuItem>
            </Security>
            <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
              <MenuItem onClick={() => handleExportJson(workspace)}>{t_i18n('Export')}</MenuItem>
            </Security>
            <Security needs={[EXPLORE_EXUPDATE_EXDELETE]} hasAccess={canManage}>
              <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
            </Security>
            {isFeatureEnable('PUBLIC_DASHBOARD_LIST') && (
              <>
                <MenuItem onClick={() => goToPublicDashboards()}>
                  {t_i18n('View associated public dashboards')}
                </MenuItem>
                <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
                  <MenuItem onClick={handleOpenCreation}>{t_i18n('Create a public dashboard')}</MenuItem>
                </Security>
              </>
            )}
          </>
        )}
        {workspace.type === 'investigation' && (
          <Security needs={[INVESTIGATION_INUPDATE_INDELETE]} hasAccess={canManage}>
            <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
          </Security>
        )}
      </Menu>
      <Drawer
        title={t_i18n('Create a public dashboard')}
        open={displayCreate}
        onClose={handleCloseCreate}
      >
        {({ onClose }) => (
          <PublicDashboardCreationForm
            onClose={handleCloseCreate}
            onCompleted={onClose}
            dashboard_id={workspace.id || undefined}
          />
        )}
      </Drawer>
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
