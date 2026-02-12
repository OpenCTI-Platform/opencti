import { Grid2 as Grid } from '@mui/material';
import React, { useState } from 'react';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemText from '@mui/material/ListItemText';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import { graphql, useFragment } from 'react-relay';
import { SSODefinitionOverviewMappingFragment$key } from '@components/settings/sso_definitions/__generated__/SSODefinitionOverviewMappingFragment.graphql';
import ItemBoolean from '../../../../components/ItemBoolean';
import Tooltip from '@mui/material/Tooltip';
import AccessesMenu from '@components/settings/AccessesMenu';
import { EMPTY_VALUE } from '../../../../utils/String';
import Card from '@common/card/Card';
import { ConfigTypeArray, getAdvancedConfigFromData, getConfigFromData } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';

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
    organizations_management {
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
      groups_scope
    }
    configuration {
      key
      value
      type
    }
  }
`;

interface SSODefinitionOverviewMappingProps {
  sso: SSODefinitionOverviewMappingFragment$key;
}

const SSODefinitionOverviewMapping = ({ sso }: SSODefinitionOverviewMappingProps) => {
  const { t_i18n } = useFormatter();
  const [currentTab, setCurrentTab] = useState(0);
  const ssoOverview = useFragment(ssoDefinitionOverviewMappingFragment, sso);

  const {
    name,
    identifier,
    label,
    description,
    enabled,
    strategy,
    configuration,
    groups_management,
    organizations_management,
  } = ssoOverview;

  type Row = { key: string; value: unknown; type: string };

  const getSsoConfigRows = (): { defaultRows: Row[]; advancedRows: Row[] } => {
    const baseRows: Row[] = [
      { key: 'name', value: name, type: 'string' },
      { key: 'identifier', type: 'string', value: identifier },
      { key: 'label', type: 'string', value: label },
      { key: 'description', type: 'string', value: description },
      { key: 'enabled', type: 'boolean', value: enabled },
      { key: 'strategy', type: 'string', value: strategy },
    ];

    if (!configuration || configuration.length === 0) {
      return {
        defaultRows: baseRows,
        advancedRows: [],
      };
    }

    const configArray: ConfigTypeArray = configuration.map((config) => ({
      key: config.key,
      value: config.value ?? '',
      type: config.type ?? 'string',
    }));

    const baseConfig = getConfigFromData(configArray, strategy);
    const advancedConfig = getAdvancedConfigFromData(configArray, strategy);

    const defaultRows: Row[] = [
      ...baseRows,
      ...baseConfig.map((config) => ({
        key: config.key,
        value: config.value,
        type: config.type,
      })),
    ];

    configuration?.forEach((config) => {
      let value = config.value;
      if (config.type === 'array') value = JSON.parse(config.value).join(',');
      baseConfig.push({
        key: config.key,
        value,
        type: config.type,
      });
    });

    const advancedRows: Row[] = advancedConfig.map((config) => ({
      key: config.key,
      value: config.value,
      type: config.type,
    }));

    return { defaultRows, advancedRows };
  };

  const getGroupsRows = (): Row[] => {
    if (!groups_management) return [];
    const rows: Row[] = [
      {
        key: 'group_attributes',
        value: groups_management.group_attributes,
        type: 'array',
      },
      {
        key: 'groups_path',
        value: groups_management.groups_path,
        type: 'array',
      },
      {
        key: 'groups_mapping',
        value: groups_management.groups_mapping,
        type: 'array',
      },
      {
        key: 'read_userinfo',
        value: groups_management.read_userinfo,
        type: 'boolean',
      },
      {
        key: 'token_reference',
        value: groups_management.token_reference,
        type: 'string',
      },
    ];
    return rows.filter(
      (row) => !(strategy === 'OpenIDConnectStrategy' && row.key === 'group_attributes'),
    );
  };

  const getOrganizationsRows = (): Row[] => {
    if (!organizations_management) return [];
    return [
      {
        key: 'organizations_path',
        value: organizations_management.organizations_path,
        type: 'array',
      },
      {
        key: 'organizations_mapping',
        value: organizations_management.organizations_mapping,
        type: 'array',
      },
      {
        key: 'organizations_scope',
        value: organizations_management.organizations_scope,
        type: 'array',
      },
    ];
  };

  const renderValue = (row: Row) => {
    if (row.type === 'array' && Array.isArray(row.value)) {
      return (
        <List dense disablePadding>
          {row.value.map((item, idx) => (
            <ListItem key={idx} disableGutters>
              <ListItemText
                primary={item}
              />
            </ListItem>
          ))}
        </List>
      );
    }

    if (typeof row.value === 'object' && row.value !== null) {
      return (
        <List dense disablePadding>
          <ListItem disableGutters>
            <ListItemText
              primary={JSON.stringify(row.value, null, 2)}
            />
          </ListItem>
        </List>
      );
    }

    if (row.type === 'encrypted' && row.value !== null) {
      return (
        <List dense disablePadding>
          <ListItem disableGutters>
            <ListItemText
              primary="******"
            />
          </ListItem>
        </List>
      );
    }

    const MAX_LEN = 60;
    const truncate = (value: string) =>
      value && value.length > MAX_LEN ? `${value.slice(0, MAX_LEN)}…` : value;
    return (
      <List dense disablePadding>
        <ListItem disableGutters>
          <Tooltip title={(row.value != null && String(row.value).length > MAX_LEN) ? String(row.value) : ''}>
            <ListItemText
              primary={
                row.value != null
                  ? truncate(String(row.value))
                  : ''
              }
            />
          </Tooltip>
        </ListItem>
      </List>
    );
  };

  const renderRows = (rows: Row[], title: string) => (
    <div style={{ marginTop: '20px' }}>
      <Card title={title}>
        <Box>
          <Grid container sx={{ mb: 1, fontWeight: 600 }}>
            <Grid size={{ xs: 12, md: 3 }}>
              <Typography variant="subtitle1">{t_i18n('Key')}</Typography>
            </Grid>
            <Grid size={{ xs: 12, md: 6 }}>
              <Typography variant="subtitle1">{t_i18n('Value')}</Typography>
            </Grid>
          </Grid>
          {rows.map((row) => {
            const valueIsTrue = row.value == 'true' || (row.key === 'enabled' && row.value);
            const valueIsFalse = row.value == 'false' || (row.key === 'enabled' && !row.value);
            return (
              <Grid
                container
                key={row.key}
                sx={{
                  py: 1,
                  borderTop: '1px solid',
                  borderColor: 'divider',
                }}
              >
                <Grid size={{ xs: 12, md: 3 }} sx={{ display: 'flex', alignItems: 'center' }}>
                  <Typography variant="body1">{row.key}</Typography>
                </Grid>
                <Grid size={{ xs: 12, md: 6 }} sx={{ display: 'flex', alignItems: 'center' }}>
                  {valueIsTrue
                    ? <ItemBoolean label={t_i18n('True')} status={true} />
                    : valueIsFalse
                      ? <ItemBoolean label={t_i18n('False')} status={false} />
                      : row.value ? renderValue(row) : EMPTY_VALUE}
                </Grid>
              </Grid>
            );
          })}
        </Box>
      </Card>
    </div>
  );

  const { defaultRows, advancedRows } = getSsoConfigRows();
  const groupsRows = getGroupsRows();
  const organizationsRows = getOrganizationsRows();

  const selectedCert = strategy === 'ClientCertStrategy';
  const selectedLocal = strategy === 'LocalStrategy';
  return (
    <div style={{ paddingRight: '200px' }}>
      <AccessesMenu />
      <Grid size={{ xs: 12 }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={(event, value) => setCurrentTab(value)}
          >
            <Tab label={t_i18n('Authentication configuration')} sx={{ textTransform: 'none' }} />
            {!selectedCert && !selectedLocal && (<Tab label={t_i18n('Groups configuration')} />)}
            {!selectedCert && !selectedLocal && (<Tab label={t_i18n('Organizations configuration')} />)}
          </Tabs>
        </Box>

        {currentTab === 0 && (
          <>
            {renderRows(defaultRows, t_i18n('Base configuration'))}
            {advancedRows.length > 0 && renderRows(advancedRows, t_i18n('Advanced configuration'))}
          </>
        )}

        {currentTab === 1 && !selectedCert && !selectedLocal && (
          renderRows(groupsRows, t_i18n('Groups configuration'))
        )}

        {currentTab === 2 && !selectedCert && !selectedLocal && (
          renderRows(organizationsRows, t_i18n('Organizations configuration'))
        )}
      </Grid>
    </div>
  );
};

export default SSODefinitionOverviewMapping;
