import { WarningOutlined } from '@mui/icons-material';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import AccessesMenu from '../AccessesMenu';
import SettingsOrganizationDetails from './SettingsOrganizationDetails';
import SettingsOrganizationUsers from '../users/SettingsOrganizationUsers';
import Triggers from '../common/Triggers';
import ItemIcon from '../../../../components/ItemIcon';
import { truncate } from '../../../../utils/String';
import { SettingsOrganization_organization$key } from './__generated__/SettingsOrganization_organization.graphql';
import SettingsOrganizationEdition from './SettingsOrganizationEdition';
import SettingsOrganizationHiddenTypesChipList from './SettingsOrganizationHiddenTypesChipList';
import useAuth from '../../../../utils/hooks/useAuth';
import { SETTINGS, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';

const useStyles = makeStyles({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  title: {
    float: 'left',
  },
});
const settingsOrganizationFragment = graphql`
  fragment SettingsOrganization_organization on Organization {
    id
    standard_id
    name
    description
    contact_information
    x_opencti_organization_type
    default_dashboard {
      id
      name
      authorizedMembers {
        id
      }
    }
    members {
      edges {
        node {
          ...UserLine_node
        }
      }
    }
    subOrganizations {
      edges {
        node {
          id
          standard_id
          name
        }
      }
    }
    parentOrganizations {
      edges {
        node {
          id
          standard_id
          name
        }
      }
    }
    editContext {
      name
      focusOn
    }
    ...SettingsOrganizationHiddenTypesField_organization
    ...SettingsOrganizationHiddenTypesChipList_organization
  }
`;
const SettingsOrganization = ({
  organizationData,
}: {
  organizationData: SettingsOrganization_organization$key;
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const { me } = useAuth();
  const organization = useFragment<SettingsOrganization_organization$key>(
    settingsOrganizationFragment,
    organizationData,
  );
  const subOrganizations = organization.subOrganizations?.edges ?? [];
  const parentOrganizations = organization.parentOrganizations?.edges ?? [];
  const canAccessDashboard = (
    organization.default_dashboard?.authorizedMembers || []
  ).some(({ id }) => ['ALL', organization.id].includes(id));
  const userHasSetAccessCapability = (me.capabilities ?? []).map((c) => c.name).includes(SETTINGS_SETACCESSES)
  const isOrganizationAdmin = me.administrated_organizations.map((orga) => orga?.id).includes(organization.id) && userHasSetAccessCapability;
  // TODO Check if right capability for Orga Edition
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Security needs={[SETTINGS]}>
        <SettingsOrganizationEdition
        organization={organization}
        enableReferences={useIsEnforceReference('Organization')}
        context={organization.editContext}
        />
      </Security>
      <>
        <Typography variant="h1" gutterBottom={true} className={classes.title}>
          {organization.name}
        </Typography>
        <div className="clearfix" />
      </>
      <Grid
        container={true}
        spacing={3}
        classes={{ container: classes.gridContainer }}
      >
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <SettingsOrganizationDetails settingsOrganization={organization} />
        </Grid>
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <div style={{ height: '100%' }}>
            <Typography variant="h4" gutterBottom={true}>
              {t('More information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <SettingsOrganizationHiddenTypesChipList organizationData={organization} />
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Parent organizations')}
                  </Typography>
                  <FieldOrEmpty source={parentOrganizations}>
                    <List>
                      {parentOrganizations.map((parentOrganization) => (
                        <ListItem
                          key={parentOrganization.node.id}
                          dense={true}
                          divider={true}
                          button={true}
                          component={Link}
                          to={`/dashboard/settings/accesses/organizations/${parentOrganization.node.id}`}
                        >
                          <ListItemIcon>
                            <ItemIcon type="Organization" />
                          </ListItemIcon>
                          <ListItemText
                            primary={parentOrganization.node.name}
                          />
                        </ListItem>
                      ))}
                    </List>
                  </FieldOrEmpty>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Child organizations')}
                  </Typography>
                  <FieldOrEmpty source={subOrganizations}>
                    <List>
                      {subOrganizations.map((subOrganization) => (
                        <ListItem
                          key={subOrganization.node.id}
                          dense={true}
                          divider={true}
                          button={true}
                          component={Link}
                          to={`/dashboard/settings/accesses/organizations/${subOrganization.node.id}`}
                        >
                          <ListItemIcon>
                            <ItemIcon type="Organization" />
                          </ListItemIcon>
                          <ListItemText primary={subOrganization.node.name} />
                        </ListItem>
                      ))}
                    </List>
                  </FieldOrEmpty>
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Default dashboard')}
                  </Typography>
                  <FieldOrEmpty source={organization.default_dashboard}>
                    <List>
                      <ListItem
                        dense={true}
                        divider={true}
                        button={true}
                        component={Link}
                        to={`/dashboard/workspaces/dashboards/${organization.default_dashboard?.id}`}
                      >
                        <ListItemIcon>
                          <ItemIcon type="Dashboard" />
                        </ListItemIcon>
                        <ListItemText
                          primary={truncate(
                            organization.default_dashboard?.name,
                            40,
                          )}
                        />
                        {!canAccessDashboard && (
                          <ListItemSecondaryAction>
                            <Tooltip
                              title={t(
                                'You need to authorize this organization to access this dashboard in the permissions of the workspace.',
                              )}
                            >
                              <WarningOutlined color="warning" />
                            </Tooltip>
                          </ListItemSecondaryAction>
                        )}
                      </ListItem>
                    </List>
                  </FieldOrEmpty>
                </Grid>
              </Grid>
            </Paper>
          </div>
        </Grid>
        <Triggers recipientId={organization.id} filter="organization_ids" />
        <SettingsOrganizationUsers organizationId={organization.id}  isOrganizationAdmin={isOrganizationAdmin}/>
      </Grid>
    </div>
  );
};
export default SettingsOrganization;
