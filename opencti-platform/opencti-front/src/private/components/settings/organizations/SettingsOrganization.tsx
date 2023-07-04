import { AccountBalanceOutlined, Warning } from '@mui/icons-material';
import Chip from '@mui/material/Chip';
import Grid from '@mui/material/Grid';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Paper from '@mui/material/Paper';
import Tooltip from '@mui/material/Tooltip';
import Typography from '@mui/material/Typography';
import makeStyles from '@mui/styles/makeStyles';
import * as R from 'ramda';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { Link } from 'react-router-dom';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import { useFormatter } from '../../../../components/i18n';
import { Theme } from '../../../../components/Theme';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import AccessesMenu from '../AccessesMenu';
import MembersList from '../users/MembersList';
import { SettingsOrganization_organization$key } from './__generated__/SettingsOrganization_organization.graphql';
import SettingsOrganizationDetails from './SettingsOrganizationDetails';
import SettingsOrganizationEdition from './SettingsOrganizationEdition';
import Triggers from '../common/Triggers';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
    padding: '0 200px 0 0',
  },
  gridContainer: {
    marginBottom: 20,
  },
  title: {
    float: 'left',
  },
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
    textTransform: 'uppercase',
    borderRadius: '0',
    margin: '0 5px 5px 0',
  },
}));
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
  }
`;
const SettingsOrganization = ({ organizationData }: {
  organizationData: SettingsOrganization_organization$key,
}) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const organization = useFragment<SettingsOrganization_organization$key>(settingsOrganizationFragment, organizationData);
  const usersSort = R.sortWith([R.ascend(R.pathOr('name', ['node', 'name']))]);
  const members = usersSort(organization.members?.edges ?? []);
  const subOrganizations = organization.subOrganizations?.edges ?? [];
  const parentOrganizations = organization.parentOrganizations?.edges ?? [];

  const canAccessDashboard = organization.default_dashboard?.authorizedMembers.some(({ id }) => ['ALL', organization.id].includes(id));

  return (
    <div className={classes.container}>
      <AccessesMenu />
      <SettingsOrganizationEdition
        organization={organization}
        enableReferences={useIsEnforceReference('Organization')}
        context={organization.editContext}
      />
      <div>
        <Typography
          variant="h1"
          gutterBottom={true}
          classes={{ root: classes.title }}
        >
          {organization.name}
        </Typography>
      </div>
      <div className="clearfix" />
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
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Part of')}
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
                            <AccountBalanceOutlined color="primary" />
                          </ListItemIcon>
                          <ListItemText primary={parentOrganization.node.name} />
                        </ListItem>
                      ))}
                    </List>
                  </FieldOrEmpty>
                  <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}
                  >
                    {t('Sub organizations')}
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
                            <AccountBalanceOutlined color="primary" />
                          </ListItemIcon>
                          <ListItemText primary={subOrganization.node.name} />
                        </ListItem>
                      ))}
                    </List>
                  </FieldOrEmpty>
                </Grid>
                <Grid item={true} xs={12}>
                  <Typography variant="h3" gutterBottom={true}>
                    {t('Dashboard')}
                  </Typography>
                  <FieldOrEmpty source={organization.default_dashboard}>
                    <Tooltip
                      title={!canAccessDashboard ? t('You need to add the organization in view mode for this dashboard') : undefined}
                    >
                      <Chip
                        key={organization.default_dashboard?.name}
                        classes={{ root: classes.chip }}
                        label={organization.default_dashboard?.name}
                        icon={!canAccessDashboard ? <Warning /> : undefined}
                      />
                    </Tooltip>
                  </FieldOrEmpty>
                </Grid>
              </Grid>
            </Paper>
          </div>
        </Grid>
        <Grid
          container={true}
          spacing={3}
          classes={{ container: classes.gridContainer }}
          style={{ marginTop: 10, marginLeft: 0 }}
        >
          <Triggers recipientId={organization.id} filter={'organization_ids'}/>
          <MembersList members={members} />
        </Grid>
      </Grid>
    </div>
  );
};
export default SettingsOrganization;
