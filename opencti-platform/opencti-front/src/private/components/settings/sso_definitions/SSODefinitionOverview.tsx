import React, { FunctionComponent } from 'react';
import { SSODefinitionQuery } from './__generated__/SSODefinitionQuery.graphql';
import Grid from '@mui/material/Grid2';
import SSODefinitionOverviewMapping from '@components/settings/sso_definitions/SSODefinitionOverviewMapping';
import SSODefinitionOverviewLogs from '@components/settings/sso_definitions/SSODefinitionOverviewLogs';

type SSO = NonNullable<SSODefinitionQuery['response']['singleSignOn']>;

interface SSODefinitionOverviewProps {
  sso: SSO;
}

const SSODefinitionOverview: FunctionComponent<SSODefinitionOverviewProps> = ({
  // sso,
}) => {
  return (
    <Grid container spacing={3}>
      <Grid size={{ xs: 12 }} container direction="column" spacing={3}>
        <SSODefinitionOverviewLogs />
      </Grid>
      <Grid size={{ xs: 12 }} container direction="column" spacing={3}>
        <SSODefinitionOverviewMapping />
      </Grid>
    </Grid>
  );
};

export default SSODefinitionOverview;
