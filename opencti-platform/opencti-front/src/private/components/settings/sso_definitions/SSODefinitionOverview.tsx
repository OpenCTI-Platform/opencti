import React, { FunctionComponent } from 'react';
import { Box, Typography, Chip } from '@mui/material';
import { useFormatter } from '../../../../components/i18n';
import { SSODefinitionQuery } from './__generated__/SSODefinitionQuery.graphql';

type SSO = NonNullable<SSODefinitionQuery['response']['singleSignOn']>;

interface SSODefinitionOverviewProps {
  sso: SSO;
}

const SSODefinitionOverview: FunctionComponent<SSODefinitionOverviewProps> = ({
  sso,
}) => {
  const { t_i18n } = useFormatter();
  const {
    name,
    identifier,
    label,
    description,
    enabled,
    strategy,
    organizations_management,
    groups_management,
    configuration,
  } = sso;

  return (
    <Box padding={3}>
      {/* Header */}
      <Box display="flex" alignItems="center" justifyContent="space-between">
        <Box>
          <Typography variant="h4">
            {label || name}
          </Typography>
          {identifier && (
            <Typography variant="body2" color="textSecondary">
              {identifier}
            </Typography>
          )}
        </Box>
        <Box display="flex" alignItems="center" gap={1}>
          <Chip
            size="small"
            label={enabled ? t_i18n('Enabled') : t_i18n('Disabled')}
            color={enabled ? 'success' : 'default'}
          />
          {strategy && (
            <Chip
              size="small"
              label={strategy}
              variant="outlined"
            />
          )}
        </Box>
      </Box>

      {description && (
        <Box mt={2}>
          <Typography variant="subtitle1">
            {t_i18n('Description')}
          </Typography>
          <Typography variant="body2">{description}</Typography>
        </Box>
      )}

      <Box mt={3}>
        <Typography variant="subtitle1">
          {t_i18n('Configuration')}
        </Typography>
        {configuration && configuration.length > 0 ? (
          <Box mt={1}>
            {configuration.map((conf) => (
              <Box
                key={conf.key}
                display="flex"
                justifyContent="space-between"
                borderBottom="1px solid rgba(0,0,0,0.06)"
                py={0.5}
              >
                <Typography variant="body2" sx={{ fontWeight: 500 }}>
                  {conf.key}
                </Typography>
                <Typography
                  variant="body2"
                  sx={{ ml: 2, whiteSpace: 'pre-wrap', textAlign: 'right' }}
                >
                  {conf.value}
                </Typography>
              </Box>
            ))}
          </Box>
        ) : (
          <Typography variant="body2" color="textSecondary">
            {t_i18n('No configuration defined')}
          </Typography>
        )}
      </Box>

      <Box mt={3}>
        <Typography variant="subtitle1">
          {t_i18n('Groups management')}
        </Typography>
        {groups_management ? (
          <Box mt={1}>
            {groups_management.groups_path && (
              <Typography variant="body2">
                <strong>{t_i18n('Groups path')}:</strong>{' '}
                {groups_management.groups_path}
              </Typography>
            )}
            {groups_management.groups_mapping && (
              <Typography variant="body2">
                <strong>{t_i18n('Groups mapping')}:</strong>{' '}
                {Array.isArray(groups_management.groups_mapping)
                  ? groups_management.groups_mapping.join(', ')
                  : groups_management.groups_mapping}
              </Typography>
            )}
            {typeof groups_management.read_userinfo === 'boolean' && (
              <Typography variant="body2">
                <strong>{t_i18n('Read userinfo')}:</strong>{' '}
                {groups_management.read_userinfo
                  ? t_i18n('Yes')
                  : t_i18n('No')}
              </Typography>
            )}
            {groups_management.group_attributes && (
              <Typography variant="body2">
                <strong>{t_i18n('Group attributes')}:</strong>{' '}
                {Array.isArray(groups_management.group_attributes)
                  ? groups_management.group_attributes.join(', ')
                  : groups_management.group_attributes}
              </Typography>
            )}
          </Box>
        ) : (
          <Typography variant="body2" color="textSecondary">
            {t_i18n('No groups management configured')}
          </Typography>
        )}
      </Box>

      <Box mt={3}>
        <Typography variant="subtitle1">
          {t_i18n('Organizations management')}
        </Typography>
        {organizations_management ? (
          <Box mt={1}>
            {organizations_management.organizations_path && (
              <Typography variant="body2">
                <strong>{t_i18n('Organizations path')}:</strong>{' '}
                {organizations_management.organizations_path}
              </Typography>
            )}
            {organizations_management.organizations_mapping && (
              <Typography variant="body2">
                <strong>{t_i18n('Organizations mapping')}:</strong>{' '}
                {Array.isArray(organizations_management.organizations_mapping)
                  ? organizations_management.organizations_mapping.join(', ')
                  : organizations_management.organizations_mapping}
              </Typography>
            )}
          </Box>
        ) : (
          <Typography variant="body2" color="textSecondary">
            {t_i18n('No organizations management configured')}
          </Typography>
        )}
      </Box>
    </Box>
  );
};

export default SSODefinitionOverview;
