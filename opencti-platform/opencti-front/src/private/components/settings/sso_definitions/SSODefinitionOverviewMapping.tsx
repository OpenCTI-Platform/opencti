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

  type Row = { key: string; value: unknown; mandatory: boolean };

  const getSsoConfigRows = (): Row[] => {
    const rows: Row[] = [
      { key: 'name', value: name, mandatory: true },
      { key: 'identifier', value: identifier, mandatory: true },
      { key: 'label', value: label, mandatory: false },
      { key: 'description', value: description, mandatory: false },
      { key: 'enabled', value: enabled, mandatory: true },
      { key: 'strategy', value: strategy, mandatory: true },
    ];
    const mandatoryField = [
      'entryPoint',
      'callbackUrl',
      'idpCert',
      'issuer',
    ];
    configuration?.forEach((c) => {
      const isMandatory = mandatoryField.includes(c.key);
      rows.push({
        key: c.key,
        value: c.value,
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
        mandatory: false,
      },
      {
        key: 'groups_path',
        value: groups_management.groups_path,
        mandatory: false,
      },
      {
        key: 'groups_mapping',
        value: groups_management.groups_mapping,
        mandatory: false,
      },
      {
        key: 'read_userinfo',
        value: groups_management.read_userinfo,
        mandatory: false,
      },
      {
        key: 'token_reference',
        value: groups_management.token_reference,
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
        mandatory: false,
      },
      {
        key: 'organizations_mapping',
        value: organizations_management.organizations_mapping,
        mandatory: false,
      },
      {
        key: 'organizations_scope',
        value: organizations_management.organizations_scope,
        mandatory: false,
      },
    ];
  };
  const renderMandatory = (mandatory: boolean) => {
    return (
      <ItemBoolean
        label={mandatory ? t_i18n('True') : t_i18n('False')}
        status={mandatory}
      />
    );
  };
  const renderValue = (value: unknown) => {
    if (Array.isArray(value)) {
      return (
        <List dense disablePadding>
          {value.map((item, idx) => (
            <ListItem key={idx} disableGutters>
              <ListItemText
                primary={item}
              />
            </ListItem>
          ))}
        </List>
      );
    }

    if (typeof value === 'object' && value !== null) {
      return (
        <List dense disablePadding>
          <ListItem disableGutters>
            <ListItemText
              primary={JSON.stringify(value, null, 2)}
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
          <Tooltip title={value != null && String(value).length > MAX_LEN ? String(value) : ''}>
            <ListItemText
              primary={
                value != null
                  ? truncate(String(value))
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
        <Grid size={{ xs: 12, md: 3 }}>
          <Typography variant="subtitle1">{t_i18n('Mandatory')}</Typography>
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
                ? <ItemBoolean label="True" status={true} />
                : valueIsFalse
                  ? <ItemBoolean label="False" status={false} />
                  : row.value ? renderValue(row.value) : EMPTY_VALUE}
            </Grid>

            <Grid size={{ xs: 12, md: 3 }} sx={{ display: 'flex', alignItems: 'center' }}>
              {renderMandatory(row.mandatory)}
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
            <Tab label={t_i18n('Groups configuration')} />
            <Tab label={t_i18n('Organizations configuration')} />
          </Tabs>
        </Box>
        {renderRows(rowsByTab[currentTab])}
      </Grid>
    </div>
  );
};

export default SSODefinitionOverviewMapping;
