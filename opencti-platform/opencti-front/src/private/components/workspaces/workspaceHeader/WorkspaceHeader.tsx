import React, { useState } from 'react';
import fileDownload from 'js-file-download';
import { graphql } from 'react-relay';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
import { Dashboard_workspace$data } from '@components/workspaces/dashboards/__generated__/Dashboard_workspace.graphql';
import handleExportJson from 'src/private/components/workspaces/workspaceExportHandler';
import { fetchQuery } from 'src/relay/environment';
import Security from 'src/utils/Security';
import { nowUTC } from 'src/utils/Time';
import { EXPLORE_EXUPDATE } from 'src/utils/hooks/useGranted';
import ExportButtons from 'src/components/ExportButtons';
import { useGetCurrentUserAccessRight } from 'src/utils/authorizedMembers';
import { truncate } from 'src/utils/String';
import WorkspaceWidgetConfig from 'src/private/components/workspaces/dashboards/WorkspaceWidgetConfig';
import { WorkspaceHeaderToStixReportBundleQuery$data } from '@components/workspaces/workspaceHeader/__generated__/WorkspaceHeaderToStixReportBundleQuery.graphql';
import { InvestigationGraph_fragment$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_fragment.graphql';
import WorkspaceKebabMenu from '@components/workspaces/WorkspaceKebabMenu';
import WorkspaceHeaderTagManager from '@components/workspaces/workspaceHeader/WorkspaceHeaderTagManager';
import Button from '@mui/material/Button';
import WorkspaceEditionContainer from '@components/workspaces/WorkspaceEditionContainer';
import { useFormatter } from '../../../../components/i18n';

const workspaceHeaderToStixReportBundleQuery = graphql`
  query WorkspaceHeaderToStixReportBundleQuery($id: String!) {
    workspace(id: $id) {
      toStixReportBundle
    }
  }
`;

type WorkspaceHeaderProps = {
  workspace: Dashboard_workspace$data | InvestigationGraph_fragment$data;
  variant: 'dashboard' | 'investigation';
  adjust?: () => void;
  handleDateChange?: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void
  config?: {
    startDate: string | null
    endDate: string | null
    relativeDate: string | null
  },
  handleAddWidget?: () => void;
};

const WorkspaceHeader = ({
  workspace,
  variant,
  adjust = () => {},
  handleAddWidget = () => {},
}: WorkspaceHeaderProps) => {
  const { t_i18n } = useFormatter();
  const { canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);

  const handleExportDashboard = () => handleExportJson(workspace);
  const handleDownloadAsStixReport = () => {
    fetchQuery(workspaceHeaderToStixReportBundleQuery, { id: workspace.id })
      .toPromise()
      .then((data) => {
        const result = data as WorkspaceHeaderToStixReportBundleQuery$data;
        if (result && result.workspace?.toStixReportBundle) {
          const blob = new Blob([result.workspace.toStixReportBundle], { type: 'text/json' });
          const fileName = `${nowUTC()}_(export-stix-report)_${workspace.name}.json`;
          fileDownload(blob, fileName);
        }
      });
  };

  const [displayEdit, setDisplayEdit] = useState(false);
  const handleCloseEdit = () => setDisplayEdit(false);
  const handleOpenEdit = () => {
    setDisplayEdit(true);
  };

  return (
    <>
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
          <WorkspaceHeaderTagManager
            tags={workspace.tags ?? []}
            workspaceId={workspace.id}
            canEdit={canEdit}
          />
        </div>
        <div style={{ display: 'flex' }}>
          <ExportButtons
            domElementId="container"
            name={workspace.name}
            type={workspace.type}
            adjust={adjust}
            handleDownloadAsStixReport={handleDownloadAsStixReport}
            handleExportDashboard={handleExportDashboard}
          />
          <WorkspaceKebabMenu workspace={workspace} />
          {variant === 'dashboard' && (<>
            <Security
              needs={[EXPLORE_EXUPDATE]}
              hasAccess={canEdit}
            >
              <WorkspaceWidgetConfig onComplete={handleAddWidget} workspace={workspace} />
            </Security>
          </>)}
          <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
            <Button
              variant='contained'
              disableElevation
              sx={{ marginLeft: 1 }}
              onClick={handleOpenEdit}
            >
              {t_i18n('Update')}
            </Button>
          </Security>
        </div>
      </div>
      <WorkspaceEditionContainer
        workspace={workspace}
        handleClose={handleCloseEdit}
        open={displayEdit}
        type={workspace.type}
      />
    </>
  );
};

export default WorkspaceHeader;
