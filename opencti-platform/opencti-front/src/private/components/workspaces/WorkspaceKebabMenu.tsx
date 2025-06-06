import React, { useState } from 'react';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVert from '@mui/icons-material/MoreVert';
import { Dashboard_workspace$data } from '@components/workspaces/dashboards/__generated__/Dashboard_workspace.graphql';
import { InvestigationGraph_fragment$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_fragment.graphql';
import ToggleButton from '@mui/material/ToggleButton';
import WorkspaceManageAccessDialog from '@components/workspaces/WorkspaceManageAccessDialog';
import WorkspaceTurnToContainerDialog from '@components/workspaces/WorkspaceTurnToContainerDialog';
import WorkspaceDuplicationDialog from '@components/workspaces/WorkspaceDuplicationDialog';
import { useGetCurrentUserAccessRight } from '../../../utils/authorizedMembers';
import Security from '../../../utils/Security';
import useGranted, { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE } from '../../../utils/hooks/useGranted';
import { useFormatter } from '../../../components/i18n';

interface WorkspaceKebabMenuProps {
  variant: 'dashboard' | 'investigation';
  workspace: Dashboard_workspace$data | InvestigationGraph_fragment$data;
}

export default function WorkspaceKebabMenu({
  variant,
  workspace,
}: WorkspaceKebabMenuProps) {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLElement, MouseEvent>) => {
    setAnchorEl(event.currentTarget);
  };

  const handleClose = () => {
    setAnchorEl(null);
  };

  const { t_i18n } = useFormatter();

  const { canManage } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);
  const isGrantedToUpdateDashboard = useGranted([EXPLORE_EXUPDATE]);

  const [displayDuplicate, setDisplayDuplicate] = useState<boolean>(false);
  const [duplicating, setDuplicating] = useState<boolean>(false);
  const handleDashboardDuplication = isGrantedToUpdateDashboard ? () => {
    handleClose();
    setDisplayDuplicate(true);
  } : () => {};
  const handleCloseDuplicate = () => setDisplayDuplicate(false);

  const [displayManageAccess, setDisplayManageAccess] = useState<boolean>(false);
  const handleOpenManageAccess = () => {
    handleClose();
    setDisplayManageAccess(true);
  };
  const handleCloseManageAccess = () => setDisplayManageAccess(false);

  const [isAddToContainerDialogOpen, setIsAddToContainerDialogOpen] = useState<boolean>(false);
  const handleOpenTurnToReportOrCaseContainer = () => {
    handleClose();
    setIsAddToContainerDialogOpen(true);
  };
  const handleCloseTurnToReportOrCaseContainer = () => setIsAddToContainerDialogOpen(false);

  return (
    <div>
      <ToggleButton
        value={'More actions'}
        size="small"
        color="primary"
        id="workspace-kebab-button"
        aria-controls={open ? 'workspace-kebab-menu' : undefined}
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={handleClick}
      >
        <MoreVert color="primary" />
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
          <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
            <MenuItem onClick={handleDashboardDuplication}>{t_i18n('Duplicate the dashboard')}</MenuItem>
          </Security>
        )}
      </Menu>

      <WorkspaceManageAccessDialog
        workspaceId={workspace.id}
        open={displayManageAccess}
        authorizedMembersData={workspace}
        owner={workspace.owner}
        handleClose={handleCloseManageAccess}
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
          workspace={workspace}
          displayDuplicate={displayDuplicate}
          handleCloseDuplicate={handleCloseDuplicate}
          duplicating={duplicating}
          setDuplicating={setDuplicating}
        />
      )}
    </div>
  );
}
