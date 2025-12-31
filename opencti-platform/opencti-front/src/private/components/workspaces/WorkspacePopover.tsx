import React, { UIEvent, useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import IconButton from '@common/button/IconButton';
import Box from '@mui/material/Box';
import MoreVert from '@mui/icons-material/MoreVert';
import { useNavigate } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import { RecordSourceSelectorProxy } from 'relay-runtime';
import PublicDashboardCreationForm from './dashboards/public_dashboards/PublicDashboardCreationForm';
import Drawer from '../common/drawer/Drawer';
import { useFormatter } from '../../../components/i18n';
import WorkspaceEditionContainer from './WorkspaceEditionContainer';
import Security from '../../../utils/Security';
import { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_EXDELETE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE_INDELETE } from '../../../utils/hooks/useGranted';
import { deleteNode, insertNode } from '../../../utils/store';
import handleExportJson from './workspaceExportHandler';
import WorkspaceDuplicationDialog from './WorkspaceDuplicationDialog';
import useApiMutation from '../../../utils/hooks/useApiMutation';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import stopEvent from '../../../utils/domEvent';
import DeleteDialog from '../../../components/DeleteDialog';
import useDeletion from '../../../utils/hooks/useDeletion';
import WorkspacePopoverDeletionMutation from './WorkspacePopoverDeletionMutation';
import { WorkspacesLinesPaginationQuery$variables } from './__generated__/WorkspacesLinesPaginationQuery.graphql';
import { WorkspacePopoverFragment$key } from './__generated__/WorkspacePopoverFragment.graphql';

const workspacePopoverFragment = graphql`
  fragment WorkspacePopoverFragment on Workspace {
    id
    type
    name
    currentUserAccessRight
    ...WorkspaceEditionContainer_workspace
    ...WorkspaceDuplicationDialogFragment
  }
`;

interface WorkspacePopoverProps {
  data: WorkspacePopoverFragment$key;
  paginationOptions: WorkspacesLinesPaginationQuery$variables;
}

const WorkspacePopover = ({ data, paginationOptions }: WorkspacePopoverProps) => {
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();

  const workspace = useFragment(workspacePopoverFragment, data);
  const {
    id,
    type,
    currentUserAccessRight,
  } = workspace;

  const [anchorEl, setAnchorEl] = useState<Element | null>(null);
  const [displayEdit, setDisplayEdit] = useState(false);
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const [duplicating, setDuplicating] = useState(false);

  const handleOpen = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(event.currentTarget);
  };

  const handleClose = (event: UIEvent) => {
    stopEvent(event);
    setAnchorEl(null);
  };

  const handleCloseDuplicate = (event?: UIEvent) => {
    if (event) stopEvent(event);
    setDisplayDuplicate(false);
  };

  const [commit] = useApiMutation(WorkspacePopoverDeletionMutation);

  const updater = (store: RecordSourceSelectorProxy) => {
    if (paginationOptions) {
      insertNode(store, 'Pagination_workspaces', paginationOptions, 'workspaceDuplicate');
    }
  };

  const deletion = useDeletion({ handleClose: () => setAnchorEl(null) });
  const { setDeleting, handleOpenDelete, handleCloseDelete } = deletion;

  const submitDelete = (event: UIEvent) => {
    stopEvent(event);
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
        handleClose(event);
        if (paginationOptions) {
          handleCloseDelete(event);
        } else {
          navigate(`/dashboard/workspaces/${type}s`);
        }
      },
    });
  };

  const handleOpenEdit = (event: UIEvent) => {
    setDisplayEdit(true);
    handleClose(event);
  };

  const handleDashboardDuplication = (event: UIEvent) => {
    setDisplayDuplicate(true);
    handleClose(event);
  };

  const handleCloseEdit = () => setDisplayEdit(false);

  const { canManage, canEdit } = useGetCurrentUserAccessRight(currentUserAccessRight);
  if (!canEdit && type !== 'dashboard') {
    return <></>;
  }

  const goToPublicDashboards = (event: UIEvent) => {
    stopEvent(event);

    const filter = {
      mode: 'and',
      filterGroups: [],
      filters: [{
        key: 'dashboard_id',
        values: [id],
        mode: 'or',
        operator: 'eq',
      }],
    };
    navigate(`/dashboard/workspaces/dashboards_public?filters=${JSON.stringify(filter)}`);
  };

  // -- Creation public dashboard --
  const [displayCreate, setDisplayCreate] = useState(false);

  const handleOpenCreation = (event: UIEvent) => {
    setDisplayCreate(true);
    handleClose(event);
  };

  const handleCloseCreate = () => {
    setDisplayCreate(false);
  };

  const handleExport = (event: UIEvent) => {
    stopEvent(event);
    handleExportJson(workspace);
  };

  return (
    <div>
      <IconButton
        onClick={handleOpen}
        aria-haspopup="true"
        size="small"
        color="primary"
        aria-label={t_i18n('Workspace popover of actions')}
      >
        <MoreVert />
      </IconButton>
      <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose} aria-label="Workspace menu">
        <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
          <MenuItem onClick={handleOpenEdit}>{t_i18n('Update')}</MenuItem>
        </Security>
        {type === 'dashboard' && (
          <Box>
            <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
              <MenuItem onClick={handleDashboardDuplication}>{t_i18n('Duplicate')}</MenuItem>
            </Security>
            <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
              <MenuItem onClick={handleExport}>{t_i18n('Export')}</MenuItem>
            </Security>
            <Security needs={[EXPLORE_EXUPDATE_EXDELETE]} hasAccess={canManage}>
              <MenuItem onClick={handleOpenDelete}>{t_i18n('Delete')}</MenuItem>
            </Security>
            <Box>
              <MenuItem onClick={goToPublicDashboards}>
                {t_i18n('View associated public dashboards')}
              </MenuItem>
              <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
                <MenuItem onClick={handleOpenCreation}>{t_i18n('Create a public dashboard')}</MenuItem>
              </Security>
            </Box>
          </Box>
        )}
        {type === 'investigation' && (
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
            onCancel={handleCloseCreate}
            onCompleted={onClose}
            dashboard_id={id || undefined}
          />
        )}
      </Drawer>
      <WorkspaceDuplicationDialog
        data={workspace}
        displayDuplicate={displayDuplicate}
        handleCloseDuplicate={handleCloseDuplicate}
        duplicating={duplicating}
        setDuplicating={setDuplicating}
        updater={updater}
        paginationOptions={paginationOptions}
      />
      <DeleteDialog
        deletion={deletion}
        submitDelete={submitDelete}
        message={type === 'investigation'
          ? t_i18n('Do you want to delete this investigation?')
          : t_i18n('Do you want to delete this dashboard?')}
      />
      <WorkspaceEditionContainer
        workspace={workspace}
        handleClose={handleCloseEdit}
        open={displayEdit}
        type={type}
      />
    </div>
  );
};

export default WorkspacePopover;
