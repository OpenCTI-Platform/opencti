/* eslint-disable custom-rules/classes-rule */
import React, { useRef, useState } from 'react';
import { graphql } from 'react-relay';
import SpeedDial from '@mui/material/SpeedDial';
import { SpeedDialIcon } from '@mui/material';
import SpeedDialAction from '@mui/material/SpeedDialAction';
import { CloudUploadOutlined, WidgetsOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import Button from '@mui/material/Button';
import VisuallyHiddenInput from '../../common/VisuallyHiddenInput';
import WidgetConfig from '../../widgets/WidgetConfig';
import { toB64 } from '../../../../utils/String';
import { handleError } from '../../../../relay/environment';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import Security from '../../../../utils/Security';
import { EXPLORE_EXUPDATE } from '../../../../utils/hooks/useGranted';
import { useFormatter } from '../../../../components/i18n';
import useHelper from '../../../../utils/hooks/useHelper';

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

const useStyles = makeStyles((theme) => ({
  speedDialButton: {
    backgroundColor: theme.palette.primary.main,
    color: theme.palette.primary.contrastText,
    '&:hover': {
      backgroundColor: theme.palette.primary.main,
    },
  },
}));

const WorkspaceWidgetConfig = ({ workspace, widget, onComplete, closeMenu }) => {
  const inputRef = useRef();
  const classes = useStyles();
  const { isFeatureEnable } = useHelper();
  const FAB_REPLACED = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const [commitWidgetImportMutation] = useApiMutation(workspaceImportWidgetMutation);
  const handleWidgetImport = async (event) => {
    const importedWidgetConfiguration = event.target.files[0];
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
        inputRef.current.value = null; // Reset the input uploader ref
      },
      onError: (error) => {
        inputRef.current.value = null; // Reset the input uploader ref
        handleError(error);
      },
    });
  };
  return (
    <>
      {!widget && (
      <>
        <VisuallyHiddenInput type="file" accept={'application/JSON'} ref={inputRef}
          onChange={handleWidgetImport}
        />
        <Security needs={[EXPLORE_EXUPDATE]}>
          {FAB_REPLACED && (
            <div>
              <Button
                variant='outlined'
                disableElevation
                style={{ marginTop: '2.5px', marginLeft: '4px' }}
                onClick={() => inputRef.current?.click()}
              >
                {t_i18n('Import Widget')}
              </Button>
              <Button
                variant='contained'
                disableElevation
                style={{ marginTop: '2.5px', marginLeft: '2px' }}
                onClick={() => setOpen(true)}
              >
                {t_i18n('Create Widget')}
              </Button>
            </div>
          )
          }
          {!FAB_REPLACED && (
          <SpeedDial
            style={{
              position: 'fixed',
              bottom: 30,
              right: 30,
              zIndex: 1100,
            }}
            ariaLabel="Create"
            icon={<SpeedDialIcon/>}
            FabProps={{ color: 'primary' }}
          >
            <SpeedDialAction
              title={t_i18n('Create a widget')}
              icon={<WidgetsOutlined/>}
              tooltipTitle={t_i18n('Create a widget')}
              onClick={() => setOpen(true)}
              FabProps={{ classes: { root: classes.speedDialButton } }}
            />
            <SpeedDialAction
              title={t_i18n('Import a widget')}
              icon={<CloudUploadOutlined/>}
              tooltipTitle={t_i18n('Import a widget')}
              onClick={() => inputRef?.current?.click()}
              FabProps={{ classes: { root: classes.speedDialButton } }}
            />
          </SpeedDial>
          )}
        </Security>
      </>
      )}
      <WidgetConfig
        handleWidgetImport={handleWidgetImport}
        onComplete={onComplete}
        widget={widget}
        closeMenu={closeMenu}
        inputRef={inputRef}
        setOpen={setOpen}
        open={open}
      />
    </>);
};

export default WorkspaceWidgetConfig;