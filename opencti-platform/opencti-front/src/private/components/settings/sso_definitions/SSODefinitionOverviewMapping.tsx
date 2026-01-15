import { Grid2 as Grid } from '@mui/material';
import React, { useState } from 'react';
import Card from '@common/card/Card';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useFormatter } from '../../../../components/i18n';
import { graphql, useFragment } from 'react-relay';
import { SSODefinitionOverviewMappingFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionOverviewMappingFragment.graphql';

export const ssoDefinitionOverviewMappingFragment = graphql`
  fragment SSODefinitionOverviewMappingFragment on SingleSignOn {
    id
    created_at
    updated_at
    name
    identifier
    label
    description
    enabled
    strategy
    organizations_management{
      organizations_path
      organizations_mapping
      organizations_scope
    }
    groups_management {
      group_attributes
      groups_path
      groups_mapping
      read_userinfo
      token_reference
    }
    configuration{
      key
      value
      type
    }
  }
`;

interface SSODefinitionOverviewMappingProps {
  sso: SSODefinitionOverviewMappingFragment$key;
}

const SSODefinitionOverviewMapping = (
  { sso }: SSODefinitionOverviewMappingProps,
) => {
  const { t_i18n } = useFormatter();

  const [currentTab, setCurrentTab] = useState(0);
  const handleChangeTab = (value: number) => {
    setCurrentTab(value);
  };
  const ssoOverview = useFragment(ssoDefinitionOverviewMappingFragment, sso);

  const { name, groups_management, organizations_management } = ssoOverview;
  return (
    <Grid size={{ xs: 12 }}>
      <Card
        title="SSO Mapping"
      >
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={(event, value) => handleChangeTab(value)}
          >
            <Tab label={t_i18n('SSO Configuration')} />
            <Tab label={t_i18n('Groups configuration')} />
            <Tab label={t_i18n('Organization configuration')} />
          </Tabs>
        </Box>
        <>
          {currentTab === 0 && (
            <>{name}</>
          )}
          {currentTab === 1 && (
            <>
              <>{groups_management?.group_attributes}</>
              <>{groups_management?.groups_mapping}</>
            </>
          )}
          {currentTab === 2 && (
            <>
              <>{organizations_management?.organizations_path}</>
              <>{organizations_management?.organizations_mapping}</>
            </>
          )}
        </>
      </Card>
    </Grid>
  );
};

export default SSODefinitionOverviewMapping;
