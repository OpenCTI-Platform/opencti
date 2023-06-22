import { graphql, useFragment } from 'react-relay';
import makeStyles from '@mui/styles/makeStyles';
import Typography from '@mui/material/Typography';
import React from 'react';
import Grid from '@mui/material/Grid';
import { Theme } from '../../../../components/Theme';
import { SettingsOrganization_organization$key } from './__generated__/SettingsOrganization_organization.graphql';
import AccessesMenu from '../AccessesMenu';
import OrganizationDetails from '../../entities/organizations/OrganizationDetails';

const useStyles = makeStyles<Theme>((theme) => ({
  container: {
    margin: 0,
  },
  gridContainer: {
    marginBottom: 20,
  },
}));
const settingsOrganizationFragment = graphql`
  fragment SettingsOrganization_organization on Organization {
    id
    standard_id
    name
#     ...SettingsOrganizationDetails_organization
  }
`;
// TODO Add Details fragment once created
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
        <Grid item={true} xs={6} style={{ paddingTop: 10 }}>
          <OrganizationDetails organization={organization} />
        </Grid>
      </Grid>
    </div>
  );
};
export default SettingsOrganization;
