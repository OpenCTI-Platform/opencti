import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import React from 'react';
import Grid from '@mui/material/Grid';
import { Theme } from '../../../../components/Theme';
import { SettingsOrganization_organization$key } from './__generated__/SettingsOrganization_organization.graphql';
import AccessesMenu from '../AccessesMenu';
import SettingsOrganizationDetails from './SettingsOrganizationDetails';

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
}));
const settingsOrganizationFragment = graphql`
  fragment SettingsOrganization_organization on Organization {
    id
    standard_id
    name
    ...SettingsOrganizationDetails_organization
  }
`;
const SettingsOrganization = ({ organizationData }: { organizationData: SettingsOrganization_organization$key }) => {
  const classes = useStyles();
  const organization = useFragment<SettingsOrganization_organization$key>(settingsOrganizationFragment, organizationData);
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
        <Grid item={true} xs={12} style={{ paddingTop: 10 }}>

          <SettingsOrganizationDetails settingsOrganizationFragment={organization} />
        </Grid>
      </Grid>
    </div>
  );
};
export default SettingsOrganization;
