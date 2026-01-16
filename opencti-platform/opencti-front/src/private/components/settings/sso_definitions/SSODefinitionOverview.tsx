import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid2';
import SSODefinitionOverviewMapping from '@components/settings/sso_definitions/SSODefinitionOverviewMapping';
// import SSODefinitionOverviewLogs from '@components/settings/sso_definitions/SSODefinitionOverviewLogs';
import { graphql, useFragment } from 'react-relay';
import { SSODefinitionOverviewFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionOverviewFragment.graphql';

export const ssoDefinitionOverviewFragment = graphql`
  fragment SSODefinitionOverviewFragment on SingleSignOn {
      #        ...SSODefinitionOverviewLogsFragment
      ...SSODefinitionOverviewMappingFragment
  }
`;

interface SSODefinitionOverviewProps {
  data: SSODefinitionOverviewFragment$key;
}

const SSODefinitionOverview: FunctionComponent<SSODefinitionOverviewProps> = ({ data }) => {
  const sso = useFragment(ssoDefinitionOverviewFragment, data);
  return (
    <Grid container spacing={3}>
      {/* <Grid size={{ xs: 12 }} container direction="column" spacing={3}> */}
      {/*  <SSODefinitionOverviewLogs /> */}
      {/* </Grid> */}
      <Grid size={{ xs: 12 }} container direction="column" spacing={3}>
        <SSODefinitionOverviewMapping sso={sso} />
      </Grid>
    </Grid>
  );
};

export default SSODefinitionOverview;
