import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import ToggleButton from '@mui/material/ToggleButton';
import { useNavigate } from 'react-router-dom';
import { graphql, useFragment } from 'react-relay';
import WorkspaceManageAccessDialog from '@components/workspaces/WorkspaceManageAccessDialog';
import WorkspaceTurnToContainerDialog from '@components/workspaces/WorkspaceTurnToContainerDialog';
import WorkspaceDuplicationDialog from '@components/workspaces/WorkspaceDuplicationDialog';
import Drawer from '@components/common/drawer/Drawer';
import PublicDashboardCreationForm from '@components/workspaces/dashboards/public_dashboards/PublicDashboardCreationForm';
import WorkspaceDeletion from '@components/workspaces/WorkspaceDeletion';
import { WorkspaceKebabMenuFragment$key } from './__generated__/WorkspaceKebabMenuFragment.graphql';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import Security from '../../../utils/Security';
import useGranted, { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_EXDELETE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import { useFormatter } from '../../../components/i18n';

const kebabMenuFragment = graphql`
  fragment WorkspaceKebabMenuFragment on Workspace {
    id
    type
    owner {
      id
      name
      entity_type
    }
    currentUserAccessRight
    ...WorkspaceDuplicationDialogFragment
    ...WorkspaceManageAccessDialog_authorizedMembers
  }
`;

interface WorkspaceKebabMenuProps {
  data: WorkspaceKebabMenuFragment$key;
}

const noop = () => {};

const useDuplicate = (isGranted = false, onDuplicate = noop) => {
  const [displayDuplicate, setDisplayDuplicate] = useState(false);
  const handleCloseDuplicate = () => setDisplayDuplicate(false);
  const [duplicating, setDuplicating] = useState(false);
  const handleDashboardDuplication = isGranted ? () => {
    onDuplicate();
    setDisplayDuplicate(true);
  } : noop;

  return {
    displayDuplicate,
    setDisplayDuplicate,
    handleCloseDuplicate,
    duplicating,
    setDuplicating,
    handleDashboardDuplication,
  };
};

const useManageAccess = (onManageAccess = noop) => {
  const [displayManageAccess, setDisplayManageAccess] = useState(false);
  const handleCloseManageAccess = () => setDisplayManageAccess(false);
  const handleOpenManageAccess = () => {
    onManageAccess();
    setDisplayManageAccess(true);
  };

  return { displayManageAccess, handleOpenManageAccess, handleCloseManageAccess };
};

const useAddToContainer = (onAddToContainer = noop) => {
  const [isAddToContainerDialogOpen, setIsAddToContainerDialogOpen] = useState(false);
  const handleCloseTurnToReportOrCaseContainer = () => setIsAddToContainerDialogOpen(false);
  const handleOpenTurnToReportOrCaseContainer = () => {
    onAddToContainer();
    setIsAddToContainerDialogOpen(true);
  };

  return { isAddToContainerDialogOpen, handleOpenTurnToReportOrCaseContainer, handleCloseTurnToReportOrCaseContainer };
};

const useDelete = (onDelete = noop) => {
  const [openDelete, setOpenDelete] = useState(false);
  const handleCloseDeletion = () => setOpenDelete(false);
  const handleOpenDeletion = () => {
    onDelete();
    setOpenDelete(true);
  };

  return { openDelete, handleOpenDeletion, handleCloseDeletion };
};

const WorkspaceKebabMenu = ({ data }: WorkspaceKebabMenuProps) => {
  const workspace = useFragment(kebabMenuFragment, data);
  const variant = workspace.type;
  const navigate = useNavigate();
  const { t_i18n } = useFormatter();
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLElement, MouseEvent>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleClose = () => {
    setAnchorEl(null);
  };
  const { canManage, canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);
  const isGrantedToUpdateDashboard = useGranted([EXPLORE_EXUPDATE]);

  const {
    displayDuplicate,
    duplicating,
    setDuplicating,
    handleDashboardDuplication,
    handleCloseDuplicate,
  } = useDuplicate(isGrantedToUpdateDashboard, handleClose);
  const { displayManageAccess, handleOpenManageAccess, handleCloseManageAccess } = useManageAccess(handleClose);
  const { isAddToContainerDialogOpen, handleOpenTurnToReportOrCaseContainer, handleCloseTurnToReportOrCaseContainer } = useAddToContainer(handleClose);
  const { openDelete, handleOpenDeletion, handleCloseDeletion } = useDelete(handleClose);

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

  const handleCloseCreate = () => {
    setDisplayCreate(false);
  };

  return (
    <div>
      <ToggleButton
        aria-label={t_i18n('Popover of actions workspace')}
        value="popover"
        size="small"
        color="primary"
        id="workspace-kebab-button"
        aria-controls={open ? 'workspace-kebab-menu' : undefined}
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={handleClick}
        sx={{ height: '100%' }}
      >
        <MoreVert color="primary" fontSize="small" />
      </ToggleButton>
      <Menu
        id="workspace-kebab-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={handleClose}
        anchorOrigin={{
          vertical: 'bottom',
          horizontal: 'right',
        }}
        transformOrigin={{
          vertical: 'top',
          horizontal: 'right',
        }}
        slotProps={{
          list: {
            'aria-labelledby': 'workspace-kebab-button',
          },
        }}
      >
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canManage}>
          <MenuItem onClick={handleOpenManageAccess}>{t_i18n('Manage access restriction')}</MenuItem>
        </Security>
        {variant === 'investigation' && (
          <Security needs={[INVESTIGATION_INUPDATE]}>
            <MenuItem onClick={handleOpenTurnToReportOrCaseContainer}>{t_i18n('Add to a container')}</MenuItem>
          </Security>
        )}
        {variant === 'dashboard' && (
          <>
            <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
              <MenuItem onClick={handleDashboardDuplication}>{t_i18n('Duplicate the dashboard')}</MenuItem>
            </Security>
            <MenuItem onClick={goToPublicDashboards}>
              {t_i18n('View associated public dashboards')}
            </MenuItem>
            <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
              <MenuItem onClick={handleOpenCreation}>{t_i18n('Create a public dashboard')}</MenuItem>
            </Security>
          </>
        )}
        <Security needs={[EXPLORE_EXUPDATE_EXDELETE]} hasAccess={canEdit}>
          <MenuItem onClick={handleOpenDeletion}>{t_i18n('Delete')}</MenuItem>
        </Security>
      </Menu>

      <WorkspaceManageAccessDialog
        workspaceId={workspace.id}
        open={displayManageAccess}
        authorizedMembersData={workspace}
        owner={workspace.owner}
        handleClose={handleCloseManageAccess}
      />
      <WorkspaceDeletion
        id={workspace.id}
        isOpen={openDelete}
        handleClose={handleCloseDeletion}
        workspaceType={workspace.type}
      />
      {variant === 'investigation' && (
        <WorkspaceTurnToContainerDialog
          workspace={workspace}
          open={isAddToContainerDialogOpen}
          handleClose={handleCloseTurnToReportOrCaseContainer}
        />
      )}
      {variant === 'dashboard' && (
        <WorkspaceDuplicationDialog
          data={workspace}
          displayDuplicate={displayDuplicate}
          handleCloseDuplicate={handleCloseDuplicate}
          duplicating={duplicating}
          setDuplicating={setDuplicating}
        />
      )}
      <Drawer
        title={t_i18n('Create a public dashboard')}
        open={displayCreate}
        onClose={handleCloseCreate}
      >
        {({ onClose }) => (
          <PublicDashboardCreationForm
            onCompleted={onClose}
            onCancel={onClose}
            dashboard_id={workspace.id || undefined}
          />
        )}
      </Drawer>
      <WorkspaceDuplicationDialog
        data={workspace}
        displayDuplicate={displayDuplicate}
        handleCloseDuplicate={handleCloseDuplicate}
        duplicating={duplicating}
        setDuplicating={setDuplicating}
      />
    </div>
  );
};

export default WorkspaceKebabMenu;
