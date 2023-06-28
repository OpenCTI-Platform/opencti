import React, { FunctionComponent } from 'react';
import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Grid from '@mui/material/Grid';
import Chip from '@mui/material/Chip';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import { Link } from 'react-router-dom';
import ListItemIcon from '@mui/material/ListItemIcon';
import { AccountBalanceOutlined } from '@mui/icons-material';
import ListItemText from '@mui/material/ListItemText';
import { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { SettingsOrganizationDetails_organization$key } from './__generated__/SettingsOrganizationDetails_organization.graphql';
import ExpandableMarkdown from '../../../../components/ExpandableMarkdown';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';

const styles = makeStyles<Theme>((theme) => ({
  paper: {
    height: '100%',
    minHeight: '100%',
    margin: '10px 0 0 0',
    padding: '15px',
    borderRadius: 6,
  },
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 150,
    backgroundColor: theme.palette.background.accent,
    color: theme.palette.text?.primary,
  },
}));

const SettingsOrganizationDetailsFragment = graphql`
      fragment SettingsOrganizationDetails_organization on Organization {
        id
        description
        contact_information
        x_opencti_organization_type
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

interface SettingsOrganizationDetailsProps {
  settingsOrganizationFragment: SettingsOrganizationDetails_organization$key;

}

const SettingsOrganizationDetails: FunctionComponent<
SettingsOrganizationDetailsProps
> = ({ settingsOrganizationFragment }) => {
  const { t } = useFormatter();
  const classes = styles();
  const organization = useFragment(
    SettingsOrganizationDetailsFragment,
    settingsOrganizationFragment,
  );
  const subOrganizations = organization.subOrganizations?.edges ?? [];
  const parentOrganizations = organization.parentOrganizations?.edges ?? [];

  return (
    <div style={{ height: '100%' }}>
      <Typography variant="h4" gutterBottom={true}>
        {t('Basic information')}
      </Typography>
      <Paper classes={{ root: classes.paper }} variant="outlined">
        <Grid container={true} spacing={3}>
          <Grid item={true} xs={6}>
            <Typography variant="h3" gutterBottom={true}>
              {t('Organization type')}
            </Typography>
            <Chip
              classes={{ root: classes.chip }}
              label={t(
                organization.x_opencti_organization_type
                  ? `organization_${organization.x_opencti_organization_type}`
                  : 'organization_other',
              )}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Description')}
            </Typography>
            <ExpandableMarkdown
              source={organization.description}
              limit={400}
            />
            <Typography
              variant="h3"
              gutterBottom={true}
              style={{ marginTop: 20 }}
            >
              {t('Contact information')}
            </Typography>
            <MarkdownDisplay
              content={organization.contact_information ?? ''}
              remarkGfmPlugin={true}
              commonmark={true}
            />
          </Grid>
            <Grid item={true} xs={6}>
              <Typography variant="h3" gutterBottom={true}>
                {t('Part of')}
              </Typography>
                <List>
                  {
                    parentOrganizations.length > 0 ? parentOrganizations.map((parentOrganization) => (
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
                    )) : '-'
                  }
                </List>
              <Typography variant="h3" gutterBottom={true} style={{ marginTop: 20 }}
              >
                {t('Sub organizations')}
              </Typography>
              <List>
                {
                  subOrganizations.length > 0 ? subOrganizations.map((subOrganization) => (
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
                  )) : '-'
                }
              </List>
            </Grid>
        </Grid>
      </Paper>
    </div>
  );
};

export default SettingsOrganizationDetails;
