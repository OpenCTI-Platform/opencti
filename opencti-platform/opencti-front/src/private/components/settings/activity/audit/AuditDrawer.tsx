import React, { FunctionComponent, Suspense } from 'react';
import { graphql, useLazyLoadQuery } from 'react-relay';
import { useTheme } from '@mui/styles';
import Typography from '@mui/material/Typography';
import Paper from '@mui/material/Paper';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import { Link } from 'react-router-dom';
import Drawer from '@components/common/drawer/Drawer';
import Loader from '../../../../../components/Loader';
import { useFormatter } from '../../../../../components/i18n';
import { useGenerateAuditMessage } from '../../../../../utils/history';
import type { Theme } from '../../../../../components/Theme';
import { AuditDrawerQuery } from './__generated__/AuditDrawerQuery.graphql';
import TruncatedRawValue from '@components/common/drawer/TruncatedRawValue';

interface AuditDrawerProps {
  open: boolean;
  onClose: () => void;
  logId: string;
}

const auditDrawerQuery = graphql`
  query AuditDrawerQuery($id: ID!) {
    audit(id: $id) {
      id
      entity_type
      event_type
      event_scope
      event_status
      timestamp
      context_uri
      user {
        id
        name
      }
      raw_data
      context_data {
        entity_id
        entity_type
        entity_name
        message
        from_id
        to_id
        changes {
          field
          changes_added {
            human
            raw
          }
          changes_removed {
            human
            raw
          }
        }
      }
    }
  }
`;

const AuditDrawerContent: FunctionComponent<{ logId: string }> = ({ logId }) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const data = useLazyLoadQuery<AuditDrawerQuery>(auditDrawerQuery, { id: logId });
  const log = data.audit;
  if (!log) return null;

  // We need to cast log to any or the expected type for useGenerateAuditMessage if strict
  // But generally it accepts an object with event_scope, etc.
  const message = useGenerateAuditMessage(log);
  const changes = log.context_data?.changes;

  return (
    <>
      <div>
        <Typography variant="h4" gutterBottom={true}>
          {t_i18n('Message')}
        </Typography>
        <b>{data?.audit?.user?.name}</b> {message}
      </div>
      {log.context_uri && (
        <div style={{ marginTop: 16 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Instance context')}
          </Typography>
          <Link to={log.context_uri}>View the element</Link>
        </div>
      )}
      {(log.context_data?.changes ?? []).length > 0 && (
        <div style={{ marginTop: 20 }}>
          <Paper style={{ marginTop: theme.spacing(1), position: 'relative' }}>
            <TableContainer>
              <Table sx={{ minWidth: 650 }} size="small">
                <TableHead>
                  <TableRow>
                    <TableCell style={{ fontSize: 12, fontWeight: 'bold' }}>{t_i18n('Field').toUpperCase()}</TableCell>
                    <TableCell width="40%" style={{ fontSize: 12, fontWeight: 'bold' }}>{t_i18n('Removed').toUpperCase()}</TableCell>
                    <TableCell width="40%" style={{ fontSize: 12, fontWeight: 'bold' }}>{t_i18n('Added').toUpperCase()}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {changes && changes.length > 0 ? (changes.map((row) => {
                    return (
                      <TableRow key={row?.field} hover={true}>
                        <TableCell component="th" scope="row" style={{ fontWeight: 'bold', verticalAlign: 'top' }}>
                          {row?.field}
                        </TableCell>
                        <TableCell align="left" style={{ verticalAlign: 'top' }}>
                          {row?.changes_removed && row.changes_removed.length > 0
                            ? row.changes_removed.map((s, i: number) => {
                                return (
                                  <div key={i}>
                                    <div style={{ marginBottom: 4 }}>{s.human}</div>
                                    { s.human !== s.raw && (
                                      <pre style={{ margin: 0, color: theme.palette.text?.secondary }}>
                                        <TruncatedRawValue value={s.raw} />
                                      </pre>
                                    )}
                                  </div>
                                );
                              })
                            : '-'}
                        </TableCell>
                        <TableCell align="left" style={{ verticalAlign: 'top' }}>
                          {row?.changes_added && row.changes_added.length > 0
                            ? row.changes_added.map((s, i: number) => {
                                return (
                                  <div key={i}>
                                    <div style={{ marginBottom: 4 }}>{s.human}</div>
                                    { s.human !== s.raw && (
                                      <pre style={{ margin: 0, color: theme.palette.text?.secondary }}>
                                        <TruncatedRawValue value={s.raw} />
                                      </pre>
                                    )}
                                  </div>
                                );
                              })
                            : '-'}
                        </TableCell>
                      </TableRow>
                    );
                  }))
                    : (
                        <TableRow>
                          <TableCell align="center" colSpan={3}>
                            {t_i18n('No detail available for this event')}
                          </TableCell>
                        </TableRow>
                      )}
                </TableBody>
              </Table>
            </TableContainer>
          </Paper>
        </div>
      )}
      {log.entity_type === 'Activity' && (
        <div style={{ marginTop: 20 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Raw data')}
          </Typography>
          <pre>{log.raw_data}</pre>
        </div>
      )}
    </>
  );
};

const AuditDrawer: FunctionComponent<AuditDrawerProps> = ({ open, onClose, logId }) => {
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      open={open}
      title={t_i18n('Activity raw detail')}
      onClose={onClose}
    >
      <Suspense fallback={<Loader />}>
        <AuditDrawerContent logId={logId} />
      </Suspense>
    </Drawer>
  );
};

export default AuditDrawer;
