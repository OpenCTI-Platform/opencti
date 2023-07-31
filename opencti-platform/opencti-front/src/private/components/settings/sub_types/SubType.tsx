import Typography from '@mui/material/Typography';
import React, { useMemo } from 'react';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import ItemStatusTemplate from '../../../../components/ItemStatusTemplate';
import SubTypeStatusPopover from './SubTypeWorkflowPopover';
import EntitySettingSettings from './entitySetting/EntitySettingSettings';
import { SubType_subType$key } from './__generated__/SubType_subType.graphql';
import { SubTypeEntitySettingSubscription } from './__generated__/SubTypeEntitySettingSubscription.graphql';
import EntitySettingAttributes from './entitySetting/EntitySettingAttributes';
import CustomizationMenu from '../CustomizationMenu';
import SearchInput from '../../../../components/SearchInput';
import { usePaginationLocalStorage } from '../../../../utils/hooks/useLocalStorage';
import { DataSourcesLinesPaginationQuery$variables } from '../../techniques/data_sources/__generated__/DataSourcesLinesPaginationQuery.graphql';

const useStyles = makeStyles(() => ({
  container: {
    margin: 0,
    padding: '0 200px 50px 0',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
    position: 'relative',
  },
}));

const entitySettingSubscription = graphql`
  subscription SubTypeEntitySettingSubscription($id: ID!) {
    entitySetting(id: $id) {
      id
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
  const { t } = useFormatter();
  const classes = useStyles();
  const subType = useFragment(subTypeFragment, data);
  const subTypeSettingsId = subType.settings?.id;
  if (subTypeSettingsId) {
    const config = useMemo<
    GraphQLSubscriptionConfig<SubTypeEntitySettingSubscription>
    >(
      () => ({
        subscription: entitySettingSubscription,
        variables: { id: subTypeSettingsId },
      }),
      [subType.settings],
    );
    useSubscription(config);
  }
  const { viewStorage, helpers } = usePaginationLocalStorage<DataSourcesLinesPaginationQuery$variables>(
    `view-${subType.id}-attributes`,
    { searchTerm: '' },
  );
  const { searchTerm } = viewStorage;
  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <div style={{ marginBottom: 23 }}>
        <Typography variant="h1" gutterBottom={true}>
          {t(`entity_${subType.label}`)}
        </Typography>
      </div>
      <Typography variant="h4" gutterBottom={true}>
        {t('Configuration')}
      </Typography>
      <Paper
        classes={{ root: classes.paper }}
        variant="outlined"
        style={{ marginBottom: 30 }}
      >
        <EntitySettingSettings entitySettingsData={subType.settings} />
        <div style={{ marginTop: 10 }}>
          <Typography variant="h3" gutterBottom={true}>
            {t('Workflow')}
            <SubTypeStatusPopover subTypeId={subType.id} />
          </Typography>
        </div>
        <ItemStatusTemplate
          statuses={subType.statuses}
          disabled={!subType.workflowEnabled}
        />
      </Paper>
      {subType.settings?.availableSettings.includes('attributes_configuration')
        && <>
          <Typography variant="h4" gutterBottom={true} style={{ float: 'left' }}>
            {t('Attributes')}
          </Typography>
          <div style={{ float: 'right', marginTop: -12 }}>
            <SearchInput
              variant="thin"
              onSubmit={helpers.handleSearch}
              keyword={searchTerm}
            />
          </div>
          <div className="clearfix" />
          <Paper classes={{ root: classes.paper }} variant="outlined" style={{ paddingTop: 5 }}>
            <EntitySettingAttributes
              entitySettingsData={subType.settings}
              searchTerm={searchTerm}
            ></EntitySettingAttributes>
          </Paper>
        </>
      }
    </div>
  );
};

export default SubType;
