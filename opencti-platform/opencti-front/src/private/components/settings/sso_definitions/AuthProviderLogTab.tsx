import React from 'react';
import Box from '@mui/material/Box';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Chip from '@mui/material/Chip';
import { ErrorOutlined, InfoOutlined, WarningAmberOutlined } from '@mui/icons-material';
import { useFormatter } from '../../../../components/i18n';
import type { SSODefinitionEditionFragment$data } from './__generated__/SSODefinitionEditionFragment.graphql';

interface AuthProviderLogTabProps {
  authLogHistory: SSODefinitionEditionFragment$data['authLogHistory'];
}

const levelColor = (level: string) => {
  switch (level) {
    case 'error':
      return 'error';
    case 'warn':
      return 'warning';
    default:
      return 'default';
  }
};

const LevelIcon = ({ level }: { level: string }) => {
  switch (level) {
    case 'error':
      return <ErrorOutlined fontSize="small" color="error" />;
    case 'warn':
      return <WarningAmberOutlined fontSize="small" sx={{ color: 'warning.main' }} />;
    default:
      return <InfoOutlined fontSize="small" color="action" />;
  }
};

const AuthProviderLogTab: React.FC<AuthProviderLogTabProps> = ({ authLogHistory }) => {
  const { fd } = useFormatter();

  if (!authLogHistory || authLogHistory.length === 0) {
    return (
      <Box sx={{ py: 2, color: 'text.secondary' }}>
        No log entries yet. Logs appear here when authentication attempts or provider actions occur.
      </Box>
    );
  }

  return (
    <Box sx={{ overflowX: 'auto' }}>
      <Table size="small" stickyHeader>
        <TableHead>
          <TableRow>
            <TableCell sx={{ fontWeight: 600 }}>Timestamp</TableCell>
            <TableCell sx={{ fontWeight: 600 }}>Level</TableCell>
            <TableCell sx={{ fontWeight: 600 }}>Message</TableCell>
            <TableCell sx={{ fontWeight: 600 }}>Details</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {authLogHistory.map((entry, index) => (
            <TableRow key={`${entry.timestamp}-${index}`} hover>
              <TableCell sx={{ whiteSpace: 'nowrap' }}>
                {entry.timestamp ? fd(entry.timestamp) : '—'}
              </TableCell>
              <TableCell>
                <Chip
                  size="small"
                  icon={<LevelIcon level={entry.level} />}
                  label={entry.level}
                  color={levelColor(entry.level) as 'error' | 'warning' | 'default'}
                  variant="outlined"
                />
              </TableCell>
              <TableCell>{entry.message}</TableCell>
              <TableCell sx={{ maxWidth: 280 }}>
                {entry.meta && Object.keys(entry.meta).length > 0 ? (
                  <Box
                    component="pre"
                    sx={{
                      m: 0,
                      fontSize: '0.75rem',
                      overflow: 'auto',
                      maxHeight: 80,
                      fontFamily: 'monospace',
                    }}
                  >
                    {JSON.stringify(entry.meta, null, 2)}
                  </Box>
                ) : (
                  '—'
                )}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </Box>
  );
};

export default AuthProviderLogTab;
