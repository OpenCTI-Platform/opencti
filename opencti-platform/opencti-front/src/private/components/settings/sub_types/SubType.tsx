import Typography from '@mui/material/Typography';
import React, { useMemo } from 'react';
import Paper from '@mui/material/Paper';
import Box from '@mui/material/Box';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment, useSubscription } from 'react-relay';
import EntitySettingsOverviewLayoutCustomization, {
  entitySettingsOverviewLayoutCustomizationEdit,
  entitySettingsOverviewLayoutCustomizationFragment,
} from '@components/settings/sub_types/entity_setting/EntitySettingsOverviewLayoutCustomization';
import { RestartAlt } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import IconButton from '@mui/material/IconButton';
import Tooltip from '@mui/material/Tooltip';
import {
  EntitySettingsOverviewLayoutCustomization_entitySetting$key,
} from '@components/settings/sub_types/entity_setting/__generated__/EntitySettingsOverviewLayoutCustomization_entitySetting.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemStatusTemplate from '../../../../components/ItemStatusTemplate';
import SubTypeStatusPopover from './SubTypeWorkflowPopover';
import EntitySettingSettings from './entity_setting/EntitySettingSettings';
import { SubType_subType$key } from './__generated__/SubType_subType.graphql';
import EntitySettingAttributes from './entity_setting/EntitySettingAttributes';
import CustomizationMenu from '../CustomizationMenu';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { DataSourcesLinesPaginationQuery$variables } from '../../techniques/data_sources/__generated__/DataSourcesLinesPaginationQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';
import useHelper from '../../../../utils/hooks/useHelper';
import useOverviewLayoutCustomization from '../../../../utils/hooks/useOverviewLayoutCustomization';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  paper: {
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 4,
    position: 'relative',
  },
}));

const entitySettingSubscription = graphql`
  subscription SubTypeEntitySettingSubscription($id: ID!) {
    entitySetting(id: $id) {
      ...EntitySettingSettings_entitySetting
    }
  }
`;

// -- GRAPHQL - ENTITY --

const subTypeFragment = graphql`
  fragment SubType_subType on SubType {
    id
    label
    workflowEnabled
    settings {
      id
      availableSettings
      ...EntitySettingsOverviewLayoutCustomization_entitySetting
      ...EntitySettingSettings_entitySetting
      ...EntitySettingAttributes_entitySetting
    }
    statuses {
      id
      order
      template {
        name
        color
      }
    }
  }
`;

const SubType = ({ data }: { data: SubType_subType$key }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isOverviewLayoutCustomizationEnabled = isFeatureEnable('OVERVIEW_LAYOUT_CUSTOMIZATION');
  const classes = useStyles();
  const subType = useFragment(subTypeFragment, data);
  const subTypeSettingsId = subType.settings?.id;
  if (subTypeSettingsId) {
    const config = useMemo(
      () => ({
        subscription: entitySettingSubscription,
        variables: { id: subTypeSettingsId },
      }),
      [subType.settings],
    );
    useSubscription(config);
  }
  const LOCAL_STORAGE_KEY = `${subType.id}-attributes`;
  const { viewStorage, helpers } = usePaginationLocalStorage<DataSourcesLinesPaginationQuery$variables>(
    LOCAL_STORAGE_KEY,
    { searchTerm: '' },
  );
  const { searchTerm } = viewStorage;
  const entitySetting = useFragment<EntitySettingsOverviewLayoutCustomization_entitySetting$key>(
    entitySettingsOverviewLayoutCustomizationFragment,
    subType.settings,
  );
  const [commitReset] = useApiMutation((entitySettingsOverviewLayoutCustomizationEdit));
  const resetLayout = () => {
    commitReset({
      variables: {
        ids: [entitySetting?.id],
        input: {
          key: 'overview_layout_customization',
          value: [undefined],
        },
      },
    });
  };

  const hasOverview = isOverviewLayoutCustomizationEnabled && entitySetting?.overview_layout_customization;

  const layout = useOverviewLayoutCustomization(subType.id);

  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <div style={{ marginBottom: 23 }}>
        <Typography variant="h1" gutterBottom={true}>
          {t_i18n(`entity_${subType.label}`)}
        </Typography>
      </div>
      <Grid
        container
        spacing={3}
      >
        <Grid item xs={12}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Configuration')}
          </Typography>
          <Paper
            classes={{ root: classes.paper }}
            variant="outlined"
            className={'paper-for-grid'}
          >
            <EntitySettingSettings entitySettingsData={subType.settings} />
            {subType.settings?.availableSettings.includes('workflow_configuration')
              && <>
                <div style={{ marginTop: 10 }}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Workflow')}
                    <SubTypeStatusPopover subTypeId={subType.id} />
                  </Typography>
                </div>
                <ItemStatusTemplate
                  statuses={subType.statuses}
                  disabled={!subType.workflowEnabled}
                />
              </>
            }
          </Paper>
        </Grid>
        {subType.settings?.availableSettings.includes('attributes_configuration') && (
          <Grid item xs={12}>
            <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
              {t_i18n('Attributes')}
            </Typography>
            <div style={{ float: 'right', marginTop: -12 }}>
              <SearchInput
                variant="thin"
                onSubmit={helpers.handleSearch}
                keyword={searchTerm}
              />
            </div>
            <div className="clearfix" />
            <Paper classes={{ root: classes.paper }} variant="outlined" className={'paper-for-grid'}>
              <EntitySettingAttributes
                entitySettingsData={subType.settings}
                searchTerm={searchTerm}
              ></EntitySettingAttributes>
            </Paper>
          </Grid>
        )}
        {hasOverview && (
          <>
            <Grid item xs={6}>
              <Typography variant="h4" gutterBottom={true} sx={{ marginBottom: 3 }}>
                <Box sx={{ display: 'inline-flex', alignItems: 'center' }}>
                  <span>{t_i18n('Overview layout customization')}</span>
                  <IconButton
                    onClick={() => resetLayout()}
                    aria-haspopup="true"
                    sx={{ marginLeft: 1 }}
                    size="small"
                    color="primary"
                  >
                    <Tooltip title={t_i18n('Reset to default layout')} >
                      <RestartAlt fontSize={'small'} color={'primary'} />
                    </Tooltip>
                  </IconButton>
                </Box>
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                variant="outlined"
                className={'paper-for-grid'}
              >
                <EntitySettingsOverviewLayoutCustomization
                  entitySettingsData={entitySetting as {
                    readonly id: string;
                    readonly overview_layout_customization: ReadonlyArray<{
                      readonly key: string;
                      readonly label: string;
                      readonly width: number;
                    }>
                  }}
                />
              </Paper>
            </Grid>
            <Grid item xs={6}>
              <Typography variant="h4" gutterBottom={true} sx={{ marginTop: 1, marginBottom: 2 }}>
                {t_i18n('Preview')}
              </Typography>
              <Paper
                classes={{ root: classes.paper }}
                variant="outlined"
                className={'paper-for-grid'}
              >
                <Grid container>
                  {layout.map(({ key, width, label }) => (
                    <Grid item xs={width} key={key}>
                      <Paper
                        classes={{ root: classes.paper }}
                        className={'paper-for-grid'}
                        style={{ height: 70, padding: 0, margin: 3, display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                      >
                        {t_i18n(label)}
                      </Paper>
                    </Grid>
                  ))}
                </Grid>
              </Paper>
            </Grid>
          </>
        )}
      </Grid>
    </div>
  );
};

export default SubType;
