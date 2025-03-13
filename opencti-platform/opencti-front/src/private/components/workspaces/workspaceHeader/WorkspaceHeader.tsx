import React, { useState } from 'react';
import fileDownload from 'js-file-download';
import { graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import ToggleButtonGroup from '@mui/material/ToggleButtonGroup';
import ToggleButton from '@mui/material/ToggleButton';
import { LockPersonOutlined, MoveToInboxOutlined } from '@mui/icons-material';
import Tooltip from '@mui/material/Tooltip';
import { Dashboard_workspace$data } from '@components/workspaces/dashboards/__generated__/Dashboard_workspace.graphql';
import WorkspaceShareButton from 'src/private/components/workspaces/WorkspaceShareButton';
import WorkspaceDuplicationDialog from 'src/private/components/workspaces/WorkspaceDuplicationDialog';
import handleExportJson from 'src/private/components/workspaces/workspaceExportHandler';
import WorkspaceTurnToContainerDialog from 'src/private/components/workspaces/WorkspaceTurnToContainerDialog';
import { fetchQuery } from 'src/relay/environment';
import Security from 'src/utils/Security';
import { nowUTC } from 'src/utils/Time';
import useGranted, { EXPLORE_EXUPDATE, EXPLORE_EXUPDATE_PUBLISH, INVESTIGATION_INUPDATE } from 'src/utils/hooks/useGranted';
import WorkspacePopover from 'src/private/components/workspaces/WorkspacePopover';
import ExportButtons from 'src/components/ExportButtons';
import { useFormatter } from 'src/components/i18n';
import WorkspaceManageAccessDialog from 'src/private/components/workspaces/WorkspaceManageAccessDialog';
import { useGetCurrentUserAccessRight } from 'src/utils/authorizedMembers';
import { truncate } from 'src/utils/String';
import useHelper from 'src/utils/hooks/useHelper';
import WorkspaceWidgetConfig from 'src/private/components/workspaces/dashboards/WorkspaceWidgetConfig';
import WorkspaceHeaderTagManager from '@components/workspaces/workspaceHeader/WorkspaceHeaderTagManager';
import DashboardTimeFilters from '@components/workspaces/dashboards/DashboardTimeFilters';
import { InvestigationGraph_workspace$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_workspace.graphql';

const workspaceHeaderToStixReportBundleQuery = graphql`
  query WorkspaceHeaderToStixReportBundleQuery($id: String!) {
    workspace(id: $id) {
      toStixReportBundle
    }
  }
`;

type WorkspaceHeaderProps = {
  workspace: Dashboard_workspace$data | InvestigationGraph_workspace$data;
  variant: 'dashboard' | 'investigation';
  adjust: () => void;
  handleDateChange: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void
  config?: {
    startDate: object
    endDate: object
    relativeDate: string
  },
  handleAddWidget: () => void;
};

const WorkspaceHeader = ({
  workspace,
  config,
  variant,
  adjust,
  handleDateChange,
  handleAddWidget,
}: WorkspaceHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');

  const [displayDuplicate, setDisplayDuplicate] = useState<boolean>(false);
  const [duplicating, setDuplicating] = useState<boolean>(false);
  const [displayManageAccess, setDisplayManageAccess] = useState<boolean>(false);
  const [isAddToContainerDialogOpen, setIsAddToContainerDialogOpen] = useState<boolean>(false);

  const { canManage, canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);
  const isGrantedToUpdateDashboard = useGranted([EXPLORE_EXUPDATE]);

  const handleDashboardDuplication = () => setDisplayDuplicate(true);
  const handleCloseDuplicate = () => setDisplayDuplicate(false);

  const handleOpenManageAccess = () => setDisplayManageAccess(true);
  const handleCloseManageAccess = () => setDisplayManageAccess(false);

  const handleOpenTurnToReportOrCaseContainer = () => setIsAddToContainerDialogOpen(true);
  const handleCloseTurnToReportOrCaseContainer = () => setIsAddToContainerDialogOpen(false);

  const handleExportDashboard = () => handleExportJson(workspace);
  const handleDownloadAsStixReport = () => {
    fetchQuery(workspaceHeaderToStixReportBundleQuery, { id: workspace.id })
      .toPromise()
      .then((data) => {
        const toStixBundleData = data?.workspace?.toStixReportBundle;
        if (toStixBundleData) {
          const blob = new Blob([toStixBundleData], { type: 'text/json' });
          const fileName = `${nowUTC()}_(export-stix-report)_${workspace.name}.json`;
          fileDownload(blob, fileName);
        }
      });
  };

  return (
    <div style={{ margin: variant === 'dashboard' ? '0 20px' : 0, display: 'flex', justifyContent: 'space-between' }}>
      <div style={{ display: 'flex', alignItems: 'center' }}>
        <Tooltip title={workspace.name}>
          <Typography
            variant="h1"
            sx={{ margin: 0 }}
            style={{ marginRight: canEdit ? 0 : 10 }}
          >
            {truncate(workspace.name, 40)}
          </Typography>
        </Tooltip>
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canEdit}>
          <WorkspacePopover workspace={workspace} />
        </Security>
        {variant === 'dashboard' && !isFABReplaced && (
          <DashboardTimeFilters
            workspace={workspace}
            config={config}
            handleDateChange={handleDateChange}
          />
        )}
      </div>
      <div style={{ display: 'flex' }}>
        <div style={{ display: 'flex', alignItems: 'center', marginRight: 7 }}>
          <WorkspaceHeaderTagManager
            tags={workspace.tags ?? []}
            workspaceId={workspace.id}
            canEdit={canEdit}
          />
        </div>
        <Security needs={[EXPLORE_EXUPDATE, INVESTIGATION_INUPDATE]} hasAccess={canManage}>
          <>
            <Tooltip title={t_i18n('Manage access restriction')}>
              <ToggleButtonGroup size="small" color="warning" exclusive sx={{ marginRight: '3px' }}>
                <ToggleButton
                  aria-label={t_i18n('Manage access restriction')}
                  onClick={handleOpenManageAccess}
                  size="small"
                  value="manage-access"
                >
                  <LockPersonOutlined fontSize="small" color="primary" />
                </ToggleButton>
              </ToggleButtonGroup>
            </Tooltip>
            <WorkspaceManageAccessDialog
              workspaceId={workspace.id}
              open={displayManageAccess}
              authorizedMembersData={workspace}
              owner={workspace.owner}
              handleClose={handleCloseManageAccess}
            />
          </>
        </Security>
        {variant === 'investigation' && (
          <>
            <Security needs={[INVESTIGATION_INUPDATE]}>
              <Tooltip title={t_i18n('Add to a container')}>
                <ToggleButtonGroup size="small" color="primary" exclusive sx={{ marginRight: '3px' }}>
                  <ToggleButton
                    aria-label="Label"
                    onClick={handleOpenTurnToReportOrCaseContainer}
                    size="small"
                    value="add-to-a-container"
                  >
                    <MoveToInboxOutlined color="primary" fontSize="small" />
                  </ToggleButton>
                </ToggleButtonGroup>
              </Tooltip>
            </Security>
            <WorkspaceTurnToContainerDialog
              workspace={workspace}
              open={isAddToContainerDialogOpen}
              handleClose={handleCloseTurnToReportOrCaseContainer}
            />
          </>
        )}
        <ExportButtons
          domElementId="container"
          name={workspace.name}
          type={workspace.type}
          adjust={adjust}
          handleDownloadAsStixReport={handleDownloadAsStixReport}
          handleExportDashboard={handleExportDashboard}
          handleDashboardDuplication={isGrantedToUpdateDashboard && handleDashboardDuplication}
          variant={variant}
        />
        {variant === 'dashboard' && (
          <Security needs={[EXPLORE_EXUPDATE_PUBLISH]} hasAccess={canManage}>
            <WorkspaceShareButton workspaceId={workspace.id} />
          </Security>
        )}
        {variant === 'dashboard' && isFABReplaced && (
          <Security
            needs={[EXPLORE_EXUPDATE]}
            hasAccess={canEdit}
          >
            <WorkspaceWidgetConfig onComplete={handleAddWidget} workspace={workspace} />
          </Security>
        )}
        <WorkspaceDuplicationDialog
          workspace={workspace}
          displayDuplicate={displayDuplicate}
          handleCloseDuplicate={handleCloseDuplicate}
          duplicating={duplicating}
          setDuplicating={setDuplicating}
        />
      </div>
    </div>
  );
};

export default WorkspaceHeader;
