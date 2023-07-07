import React from 'react';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Grid from '@mui/material/Grid';
import Paper from '@mui/material/Paper';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { AccountBalanceOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import * as R from 'ramda';
import { Theme } from '../../../../components/Theme';
import { SettingsOrganization_organization$key } from './__generated__/SettingsOrganization_organization.graphql';
import AccessesMenu from '../AccessesMenu';
import SettingsOrganizationDetails from './SettingsOrganizationDetails';
import { useFormatter } from '../../../../components/i18n';
import FieldOrEmpty from '../../../../components/FieldOrEmpty';
import MembersList from '../users/MembersList';
import Triggers from '../common/Triggers';

const useStyles = makeStyles<Theme>(() => ({
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
}));
const settingsOrganizationFragment = graphql`
  fragment SettingsOrganization_organization on Organization {
    id
    standard_id
    name
    description
    contact_information
    x_opencti_organization_type
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
  }
`;
const SettingsOrganization = ({ organizationData }: { organizationData: SettingsOrganization_organization$key }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const organization = useFragment<SettingsOrganization_organization$key>(settingsOrganizationFragment, organizationData);
  const usersSort = R.sortWith([R.ascend(R.pathOr('name', ['node', 'name']))]);
  const members = usersSort(organization.members?.edges ?? []);
  const subOrganizations = organization.subOrganizations?.edges ?? [];
  const parentOrganizations = organization.parentOrganizations?.edges ?? [];

  return (
    <div className={classes.container}>
      <AccessesMenu />
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
