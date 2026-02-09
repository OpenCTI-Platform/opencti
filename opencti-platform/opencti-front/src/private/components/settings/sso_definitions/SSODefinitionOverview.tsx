import React, { FunctionComponent } from 'react';
import Grid from '@mui/material/Grid2';
import SSODefinitionOverviewMapping from '@components/settings/sso_definitions/SSODefinitionOverviewMapping';
// import SSODefinitionOverviewLogs from '@components/settings/sso_definitions/SSODefinitionOverviewLogs';
import { graphql, useFragment } from 'react-relay';
import { SSODefinitionOverviewFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionOverviewFragment.graphql';
import Alert from '../../../../components/Alert';
import { useFormatter } from '../../../../components/i18n';
import { SSODefinitionQuery$data } from '@components/settings/sso_definitions/__generated__/SSODefinitionQuery.graphql';

export const ssoDefinitionOverviewFragment = graphql`
  fragment SSODefinitionOverviewFragment on SingleSignOn {
      #        ...SSODefinitionOverviewLogsFragment
      ...SSODefinitionOverviewMappingFragment
  }
`;

interface SSODefinitionOverviewProps {
  data: SSODefinitionOverviewFragment$key;
  singleSignOnSettings: SSODefinitionQuery$data['singleSignOnSettings'];
}

const SSODefinitionOverview: FunctionComponent<SSODefinitionOverviewProps> = ({ data, singleSignOnSettings }) => {
  const { t_i18n } = useFormatter();
  const sso = useFragment(ssoDefinitionOverviewFragment, data);
  const isForceEnv = singleSignOnSettings?.is_force_env;

  return (
    <Grid container spacing={3}>
      {/* <Grid size={{ xs: 12 }} container direction="column" spacing={3}> */}
      {/*  <SSODefinitionOverviewLogs /> */}
      {/* </Grid> */}
      {isForceEnv && (
        <Alert
          content={t_i18n('Authentication configuration is currently forced by configuration to be with environment variable only, Authentication can still be configured with the UI to prepare configuration but changes will not applied until the app.authentication.force_env is removed or set to false.')}
          severity="warning"
          style={{ marginBottom: 20, paddingRight: 200 }}
        />
      )}
      <Grid size={{ xs: 12 }} container direction="column" spacing={3}>
        <SSODefinitionOverviewMapping sso={sso} />
      </Grid>
    </Grid>
  );
};

export default SSODefinitionOverview;
