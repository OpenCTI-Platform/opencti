import Grid from '@mui/material/Grid';
import Typography from '@mui/material/Typography';
import React, { useMemo } from 'react';
import Paper from '@mui/material/Paper';
import makeStyles from '@mui/styles/makeStyles';
import { graphql, useFragment, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useFormatter } from '../../../../components/i18n';
import ItemStatusTemplate from '../../../../components/ItemStatusTemplate';
import SubTypeStatusPopover from './SubTypeWorkflowPopover';
import EntitySetting from './EntitySetting';
import { SubType_subType$key } from './__generated__/SubType_subType.graphql';
import EntitySettingAttributesConfiguration from './EntitySettingAttributesConfiguration';
import EntitySettingAttributesConfigurationScale from './EntitySettingAttributesConfigurationScale';
import { SubTypeEntitySettingSubscription } from './__generated__/SubTypeEntitySettingSubscription.graphql';
import CustomizationMenu from '../CustomizationMenu';

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

export const entitySettingSubscription = graphql`
  subscription SubTypeEntitySettingSubscription($id: ID!) {
    entitySetting(id: $id) {
      ...EntitySetting_entitySetting
    }
  }
`;

// -- GRAPHQL - ENTITY --

export const subTypeFragment = graphql`
  fragment SubType_subType on SubType {
    id
    label
    workflowEnabled
    settings {
      id
      ...EntitySetting_entitySetting
    }
    statuses {
      edges {
        node {
          id
          order
          template {
            name
            color
          }
        }
      }
    }
  }
`;

const SubType = ({ data }: { data: SubType_subType$key }) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const subType = useFragment(subTypeFragment, data);
  const statuses = (subType.statuses?.edges ?? []).map((edge) => edge.node);

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

  return (
    <div className={classes.container}>
      <CustomizationMenu />
      <div style={{ marginBottom: 23 }}>
        <Typography variant="h1" gutterBottom={true}>
          {t(`entity_${subType.label}`)}
        </Typography>
      </div>
      <Grid container={true} spacing={3} style={{ marginBottom: 20 }}>
        <Grid item={true} xs={6}>
          <div style={{ height: '100%' }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('Configuration')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <EntitySetting entitySettingsData={subType.settings} />
              <div style={{ marginTop: 10 }}>
                <Typography variant="h3" gutterBottom={true}>
                  {t('Workflow')}
                  <SubTypeStatusPopover subTypeId={subType.id} />
                </Typography>
              </div>
              <ItemStatusTemplate
                statuses={statuses}
                disabled={!subType.workflowEnabled}
              />
            </Paper>
          </div>
        </Grid>
        <EntitySettingAttributesConfiguration
          entitySettingsData={subType.settings}
        />
        <EntitySettingAttributesConfigurationScale
          entitySettingsData={subType.settings}
        />
      </Grid>
    </div>
  );
};

export default SubType;
