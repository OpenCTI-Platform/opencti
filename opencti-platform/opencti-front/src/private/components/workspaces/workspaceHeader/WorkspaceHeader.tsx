import React, { useState } from 'react';
import fileDownload from 'js-file-download';
import { graphql, useFragment } from 'react-relay';
import Typography from '@mui/material/Typography';
import Tooltip from '@mui/material/Tooltip';
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
import WorkspaceKebabMenu from '@components/workspaces/WorkspaceKebabMenu';
import WorkspaceHeaderTagManager from '@components/workspaces/workspaceHeader/WorkspaceHeaderTagManager';
import Button from '@common/button/Button';
import WorkspaceEditionContainer from '@components/workspaces/WorkspaceEditionContainer';
import { WorkspaceHeaderFragment$key } from '@components/workspaces/workspaceHeader/__generated__/WorkspaceHeaderFragment.graphql';
import { useFormatter } from '../../../../components/i18n';

const workspaceHeaderFragment = graphql`
  fragment WorkspaceHeaderFragment on Workspace {
    id
    name
    tags
    type
    currentUserAccessRight
    ...WorkspaceKebabMenuFragment
    ...WorkspaceEditionContainer_workspace
  }
`;

const workspaceHeaderToStixReportBundleQuery = graphql`
  query WorkspaceHeaderToStixReportBundleQuery($id: String!) {
    workspace(id: $id) {
      toStixReportBundle
    }
  }
`;

type WorkspaceHeaderProps = {
  data: WorkspaceHeaderFragment$key;
  variant: 'dashboard' | 'investigation';
  adjust?: () => void;
  handleDateChange?: (type: 'startDate' | 'endDate' | 'relativeDate', value: string | null) => void;
  config?: {
    startDate: string | null;
    endDate: string | null;
    relativeDate: string | null;
  };
  handleAddWidget?: () => void;
  handleImportWidget?: (widgetFile: File) => void;
};

const WorkspaceHeader = ({
  data,
  variant,
  adjust = () => {},
  handleAddWidget = () => {},
  handleImportWidget = () => {},
}: WorkspaceHeaderProps) => {
  const { t_i18n } = useFormatter();
  const workspace = useFragment(workspaceHeaderFragment, data);
  const { canEdit } = useGetCurrentUserAccessRight(workspace.currentUserAccessRight);

  const handleExportDashboard = () => handleExportJson(workspace);
  const handleDownloadAsStixReport = () => {
    fetchQuery(workspaceHeaderToStixReportBundleQuery, { id: workspace.id })
      .toPromise()
      .then((result) => {
        const resultData = result as WorkspaceHeaderToStixReportBundleQuery$data;
        if (resultData && resultData.workspace?.toStixReportBundle) {
          const blob = new Blob([resultData.workspace.toStixReportBundle], { type: 'text/json' });
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
          <WorkspaceKebabMenu data={workspace} />
          {variant === 'dashboard' && (
            <>
              <Security
                needs={[EXPLORE_EXUPDATE]}
                hasAccess={canEdit}
              >
                <WorkspaceWidgetConfig
                  onComplete={handleAddWidget}
                  handleImportWidget={handleImportWidget}
                />
              </Security>
            </>
          )}
          <Security needs={[EXPLORE_EXUPDATE]} hasAccess={canEdit}>
            <Button
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
