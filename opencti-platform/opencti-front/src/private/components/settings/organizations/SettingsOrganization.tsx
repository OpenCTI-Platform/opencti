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
import EnterpriseEdition from '@components/common/entreprise_edition/EnterpriseEdition';
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
import useGranted, { BYPASS, SETTINGS_SETACCESSES } from '../../../../utils/hooks/useGranted';
import Security from '../../../../utils/Security';
import useEnterpriseEdition from '../../../../utils/hooks/useEnterpriseEdition';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
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
    borderRadius: 4,
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
    grantable_groups {
      id
      name
      roles {
        edges {
          node {
            name
            capabilities {
              name
            }
          }
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
  const { t_i18n } = useFormatter();
  const { me } = useAuth();
  const setAccess = useGranted([SETTINGS_SETACCESSES]);
  const isEnterpriseEdition = useEnterpriseEdition();
  const organization = useFragment<SettingsOrganization_organization$key>(
    settingsOrganizationFragment,
    organizationData,
  );
  const subOrganizations = organization.subOrganizations?.edges ?? [];
  const parentOrganizations = organization.parentOrganizations?.edges ?? [];
  const canAccessDashboard = (
    organization.default_dashboard?.authorizedMembers || []
  ).some(({ id }) => ['ALL', organization.id].includes(id));
  const capabilitiesPerGroup = new Map(
    organization.grantable_groups?.map((group) => [
      group.id,
      group.roles?.edges?.map(({ node }) => node?.capabilities?.map((capa) => capa?.name)).flat(),
    ]),
  );
  const isOrganizationAdmin = (me.administrated_organizations ?? [])
    .map((orga) => orga?.id)
    .includes(organization.id);
  return (
    <div className={classes.container}>
      <AccessesMenu />
      <Security needs={[SETTINGS_SETACCESSES]}>
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
              {t_i18n('More information')}
            </Typography>
            <Paper classes={{ root: classes.paper }} variant="outlined">
              <Grid container={true} spacing={3}>
                <Grid item={true} xs={12}>
                  <SettingsOrganizationHiddenTypesChipList
                    organizationData={organization}
                  />
                </Grid>
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Parent organizations')}
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
                    {t_i18n('Child organizations')}
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
                    {t_i18n('Default dashboard')}
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
                              title={t_i18n(
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
                <Grid item={true} xs={6}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t_i18n('Grantable groups by organization administrators')}
                  </Typography>
                  <FieldOrEmpty source={organization.grantable_groups}>
                    <List>
                      {(organization.grantable_groups ?? []).map((group) => (!isOrganizationAdmin ? (
                        <ListItem
                          key={group.id}
                          dense={true}
                          divider={true}
                          button={true}
                          component={Link}
                          to={`/dashboard/settings/accesses/groups/${group.id}`}
                        >
                          <ListItemIcon>
                            <ItemIcon type="Group" />
                          </ListItemIcon>
                          <ListItemText primary={group.name} />
                          {(capabilitiesPerGroup
                            .get(group.id)
                            ?.includes(SETTINGS_SETACCESSES)
                              || capabilitiesPerGroup
                                .get(group.id)
                                ?.includes(BYPASS)) && (
                                <Tooltip
                                  title={t_i18n(
                                    'This Group allows the user to bypass restriction. It should not be added here.',
                                  )}
                                >
                                  <WarningOutlined color="warning" />
                                </Tooltip>
                          )}
                        </ListItem>
                      ) : (
                        <ListItem key={group.id} dense={true} divider={true}>
                          <ListItemIcon>
                            <ItemIcon type="Group" />
                          </ListItemIcon>
                          <ListItemText primary={group.name} />
                          {(capabilitiesPerGroup
                            .get(group.id)
                            ?.includes(SETTINGS_SETACCESSES)
                              || capabilitiesPerGroup
                                .get(group.id)
                                ?.includes(BYPASS)) && (
                                <Tooltip
                                  title={t_i18n(
                                    'This Group allows the user to bypass restriction. It should not be added here.',
                                  )}
                                >
                                  <WarningOutlined color="warning" />
                                </Tooltip>
                          )}
                        </ListItem>
                      )))}
                    </List>
                  </FieldOrEmpty>
                </Grid>
              </Grid>
            </Paper>
          </div>
        </Grid>
        {setAccess || isEnterpriseEdition ? (
          <>
            <Triggers recipientId={organization.id} filterKey="authorized_members.id" />
            <SettingsOrganizationUsers organization={organization} />
          </>
        ) : (
          <Grid item={true} xs={12} style={{ marginTop: 30 }}>
            <EnterpriseEdition
              feature={t_i18n('Organization sharing')}
            />
          </Grid>
        )}
      </Grid>
    </div>
  );
};
export default SettingsOrganization;
