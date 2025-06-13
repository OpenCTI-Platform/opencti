import React, { useRef, useState } from 'react';
import { graphql } from 'react-relay';
import Button from '@mui/material/Button';
import MenuItem from '@mui/material/MenuItem';
import { Dashboard_workspace$data } from '@components/workspaces/dashboards/__generated__/Dashboard_workspace.graphql';
import { Widget } from 'src/utils/widget/widget';
import { InvestigationGraph_fragment$data } from '@components/workspaces/investigations/__generated__/InvestigationGraph_fragment.graphql';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import WidgetConfig from '../../widgets/WidgetConfig';
import { toB64 } from '../../../../utils/String';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';

const workspaceImportWidgetMutation = graphql`
  mutation WorkspaceWidgetConfigImportMutation(
    $id: ID!
    $input: ImportConfigurationInput!
  ) {
    workspaceWidgetConfigurationImport(id: $id, input: $input) {
      manifest
      ...Dashboard_workspace
    }
  }
`;

type WorkspaceWidgetConfigProps = {
  workspace: Dashboard_workspace$data | InvestigationGraph_fragment$data;
  widget?: Widget,
  onComplete: (value: Widget, variableName?: string) => void,
  closeMenu?: () => void;
};

const WorkspaceWidgetConfig = ({ workspace, widget, onComplete, closeMenu }: WorkspaceWidgetConfigProps) => {
  const { t_i18n } = useFormatter();

  const [isWidgetConfigOpen, setIsWidgetConfigOpen] = useState<boolean>(false);

  const [commitWidgetImportMutation] = useApiMutation(workspaceImportWidgetMutation);
  const inputRef: React.MutableRefObject<HTMLInputElement | null> = useRef(null);

  const handleWidgetImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const importedWidgetConfiguration = event.target.files?.[0];
    const emptyDashboardManifest = toB64(JSON.stringify({ widgets: {}, config: {} }));
    const dashboardManifest = workspace.manifest ?? emptyDashboardManifest;
    commitWidgetImportMutation({
      variables: {
        id: workspace.id,
        input: {
          importType: 'widget',
          file: importedWidgetConfiguration,
          dashboardManifest,
        },
      },
      updater: () => {
        if (inputRef.current) inputRef.current.value = ''; // Reset the input uploader ref
      },
      onError: (error) => {
        if (inputRef.current) inputRef.current.value = ''; // Reset the input uploader ref
        handleError(error);
      },
    });
  };

  const handleOpenWidgetConfig = () => setIsWidgetConfigOpen(true);
  const handleCloseWidgetConfig = () => setIsWidgetConfigOpen(false);

  const handleUpdateWidgetMenuClick = () => {
    closeMenu?.();
    handleOpenWidgetConfig();
  };

  const handleImportWidgetButtonClick = () => inputRef.current?.click();

  return (
    <>
      {!widget && (
        <>
          <VisuallyHiddenInput
            type="file"
            accept={'application/JSON'}
            ref={inputRef}
            onChange={handleWidgetImport}
          />
          <Security needs={[EXPLORE_EXUPDATE]}>
            <>
              <>
                <Button
                  variant='outlined'
                  disableElevation
                  sx={{ marginLeft: 1 }}
                  onClick={handleImportWidgetButtonClick}
                >
                  {t_i18n('Import Widget')}
                </Button>
                <Button
                  variant='outlined'
                  disableElevation
                  sx={{ marginLeft: 1 }}
                  onClick={handleOpenWidgetConfig}
                >
                  {t_i18n('Create Widget')}
                </Button>
              </>
            </>
          </Security>
        </>
      )}
      {widget && (
        <MenuItem onClick={handleUpdateWidgetMenuClick}>
          {t_i18n('Update')}
        </MenuItem>
      )}
      <WidgetConfig
        onComplete={onComplete}
        widget={widget}
        onClose={handleCloseWidgetConfig}
        open={isWidgetConfigOpen}
        context="workspace"
      />
    </>
  );
};

export default WorkspaceWidgetConfig;
