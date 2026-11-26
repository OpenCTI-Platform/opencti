import Card from '@common/card/Card';
import { Box, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { ProfileLoginHistory_me$key } from './__generated__/ProfileLoginHistory_me.graphql';
import { ProfileLoginHistory_settings$key } from './__generated__/ProfileLoginHistory_settings.graphql';

const profileLoginHistoryFragment = graphql`
  fragment ProfileLoginHistory_me on MeUser {
    login_history {
      id
      timestamp
      provider
    }
  }
`;

const profileLoginHistorySettingsFragment = graphql`
  fragment ProfileLoginHistory_settings on Settings {
    # The number of logins to show, set by the platform administrators. 0 hides the card
    platform_login_history_count
    platform_providers {
      name
      provider
    }
  }
`;

interface ProfileLoginHistoryProps {
  me: ProfileLoginHistory_me$key;
  settings: ProfileLoginHistory_settings$key;
}

// The last successful logins of the connected user, read from the activity log (Enterprise Edition)
const ProfileLoginHistory: React.FC<ProfileLoginHistoryProps> = ({ me, settings }) => {
  const { t_i18n, fldt } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { login_history } = useFragment(profileLoginHistoryFragment, me);
  const { platform_login_history_count, platform_providers } = useFragment(profileLoginHistorySettingsFragment, settings);
  if (!isEnterpriseEdition || (platform_login_history_count ?? 0) <= 0) {
    return null;
  }
  const logins = login_history ?? [];
  // A login records the identifier of its provider: show the name users see on the login page instead.
  // A provider removed since then is no longer listed, so its identifier is shown as is.
  const providerNames = new Map(platform_providers.map(({ provider, name }) => [provider, name]));
  const providerName = (provider: string | null | undefined) => {
    if (!provider) return '-';
    return providerNames.get(provider) ?? provider;
  };
  return (
    <Card title={t_i18n('Last logins')}>
      <Box component="p" sx={{ color: 'text.secondary', marginTop: 0, marginBottom: 2 }}>
        {t_i18n('Your last successful logins to the platform. If you do not recognize one of them, change your password and contact your administrator.')}
      </Box>
      {logins.length === 0 ? (
        <Box sx={{ textAlign: 'center', padding: '20px', color: 'text.secondary' }}>
          {t_i18n('No login recorded yet.')}
        </Box>
      ) : (
        <TableContainer>
          <Table
            size="small"
            aria-label={t_i18n('Last logins')}
            sx={{ '& .MuiTableRow-root:last-child .MuiTableCell-root': { borderBottom: 'none' } }}
          >
            <TableHead>
              <TableRow>
                <TableCell>{t_i18n('Date')}</TableCell>
                <TableCell>{t_i18n('Authentication provider')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {logins.map((login) => (
                <TableRow key={login.id}>
                  <TableCell>{fldt(login.timestamp)}</TableCell>
                  <TableCell>{providerName(login.provider)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Card>
  );
};

export default ProfileLoginHistory;
