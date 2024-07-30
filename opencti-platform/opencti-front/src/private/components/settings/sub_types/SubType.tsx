import Typography from '@mui/material/Typography';
import React, { useMemo } from 'react';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment, useSubscription } from 'react-relay';
import Grid from '@mui/material/Grid';
import EntitySettingCustomOverview from '@components/settings/sub_types/entity_setting/EntitySettingCustomOverview';
import { RootSubTypeQuery$variables } from '@components/settings/sub_types/__generated__/RootSubTypeQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import ItemStatusTemplate from '../../../../components/ItemStatusTemplate';
import SubTypeStatusPopover from './SubTypeWorkflowPopover';
import EntitySettingSettings from './entity_setting/EntitySettingSettings';
import { SubType_subType$key } from './__generated__/SubType_subType.graphql';
import EntitySettingAttributes from './entity_setting/EntitySettingAttributes';
import CustomizationMenu from '../CustomizationMenu';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import useHelper from '../../../../utils/hooks/useHelper';

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

interface SubTypeProps {
  data: SubType_subType$key;
}

const SubType: React.FC<SubTypeProps> = ({ data }) => {
  const { t_i18n } = useFormatter();
  const { isFeatureEnable } = useHelper();
  const isOverviewLayoutCustomizationEnabled = isFeatureEnable('OVERVIEW_LAYOUT_CUSTOMIZATION');
  const classes = useStyles();
  const subType = useFragment<SubType_subType$key>(subTypeFragment, data);

  const subTypeSettingsId = subType.settings?.id;
  if (!subTypeSettingsId) {
    return null;
  }
  const config = useMemo(
    () => ({
      subscription: entitySettingSubscription,
      variables: { id: subTypeSettingsId },
    }),
    [subType.settings],
  );
  useSubscription(config);

  const LOCAL_STORAGE_KEY = `${subType.id}-attributes`;
  const { viewStorage, helpers } = usePaginationLocalStorage<RootSubTypeQuery$variables>(
    LOCAL_STORAGE_KEY,
    { searchTerm: '' },
  );
  const { searchTerm } = viewStorage;

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
        { isOverviewLayoutCustomizationEnabled && (
          <EntitySettingCustomOverview
            entitySettingsData={subType.settings}
          />
        )}
      </Grid>
    </div>
  );
};

export default SubType;
