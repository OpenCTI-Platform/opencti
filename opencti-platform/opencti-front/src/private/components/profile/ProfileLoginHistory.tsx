import Card from '@common/card/Card';
import { Box, Table, TableBody, TableCell, TableContainer, TableHead, TableRow } from '@mui/material';
import React from 'react';
import { graphql, useFragment } from 'react-relay';
import { useFormatter } from '../../../components/i18n';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import { ProfileLoginHistory_me$key } from './__generated__/ProfileLoginHistory_me.graphql';

const profileLoginHistoryFragment = graphql`
  fragment ProfileLoginHistory_me on MeUser {
    login_history {
      id
      timestamp
      provider
    }
  }
`;

interface ProfileLoginHistoryProps {
  me: ProfileLoginHistory_me$key;
  // The number of logins to show, set by the platform administrators. 0 hides the card
  loginHistoryCount: number;
}

// The last successful logins of the connected user, read from the activity log (Enterprise Edition)
const ProfileLoginHistory: React.FC<ProfileLoginHistoryProps> = ({ me, loginHistoryCount }) => {
  const { t_i18n, fldt } = useFormatter();
  const isEnterpriseEdition = useEnterpriseEdition();
  const { login_history } = useFragment(profileLoginHistoryFragment, me);
  if (!isEnterpriseEdition || loginHistoryCount <= 0) {
    return null;
  }
  const logins = login_history ?? [];
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
                  <TableCell>{login.provider ?? '-'}</TableCell>
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
