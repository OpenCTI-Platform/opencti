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

  type Row = { key: string; value: unknown; type: string; mandatory: boolean };

  const getSsoConfigRows = (): Row[] => {
    const rows: Row[] = [
      { key: 'name', value: name, type: 'string', mandatory: true },
      { key: 'identifier', type: 'string', value: identifier, mandatory: true },
      { key: 'label', type: 'string', value: label, mandatory: false },
      { key: 'description', type: 'string', value: description, mandatory: false },
      { key: 'enabled', type: 'boolean', value: enabled, mandatory: true },
      { key: 'strategy', type: 'string', value: strategy, mandatory: true },
    ];

    const mandatoryField = [
      'entryPoint',
      'callbackUrl',
      'idpCert',
      'issuer',
    ];

    configuration?.forEach((config) => {
      const isMandatory = mandatoryField.includes(config.key);
      let value = config.value;
      if (config.type === 'array') value = JSON.parse(config.value).join(',');
      rows.push({
        key: config.key,
        value,
        type: config.type,
        mandatory: isMandatory,
      });
    });

    return rows;
  };

  const getGroupsRows = (): Row[] => {
    if (!groups_management) return [];
    return [
      {
        key: 'group_attributes',
        value: groups_management.group_attributes,
        type: 'array',
        mandatory: false,
      },
      {
        key: 'groups_path',
        value: groups_management.groups_path,
        type: 'array',
        mandatory: false,
      },
      {
        key: 'groups_mapping',
        value: groups_management.groups_mapping,
        type: 'array',
        mandatory: false,
      },
      {
        key: 'read_userinfo',
        value: groups_management.read_userinfo,
        type: 'boolean',
        mandatory: false,
      },
      {
        key: 'token_reference',
        value: groups_management.token_reference,
        type: 'string',
        mandatory: false,
      },
    ];
  };

  const getOrganizationsRows = (): Row[] => {
    if (!organizations_management) return [];
    return [
      {
        key: 'organizations_path',
        value: organizations_management.organizations_path,
        type: 'array',
        mandatory: false,
      },
      {
        key: 'organizations_mapping',
        value: organizations_management.organizations_mapping,
        type: 'array',
        mandatory: false,
      },
      {
        key: 'organizations_scope',
        value: organizations_management.organizations_scope,
        type: 'array',
        mandatory: false,
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

    const MAX_LEN = 70;
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

  const renderRows = (rows: Row[]) => (
    <Box sx={{ mt: 2 }}>
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
  );

  const rowsByTab = [
    getSsoConfigRows(),
    getGroupsRows(),
    getOrganizationsRows(),
  ];
  const selectedCert = strategy === 'ClientCertStrategy';
  return (
    <div style={{ paddingRight: '200px' }}>
      <AccessesMenu />
      <Grid size={{ xs: 12 }}>
        <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
          <Tabs
            value={currentTab}
            onChange={(event, value) => setCurrentTab(value)}
          >
            <Tab label={t_i18n('SSO configuration')} sx={{ textTransform: 'none' }} />
            {!selectedCert && (<Tab label={t_i18n('Groups configuration')} />)}
            {!selectedCert && (<Tab label={t_i18n('Organizations configuration')} />)}
          </Tabs>
        </Box>
        {renderRows(rowsByTab[currentTab])}
      </Grid>
    </div>
  );
};

export default SSODefinitionOverviewMapping;
