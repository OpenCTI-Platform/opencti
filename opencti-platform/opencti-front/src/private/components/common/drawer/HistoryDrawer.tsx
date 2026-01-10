import React, { FunctionComponent, Suspense, useState } from 'react';
import Typography from '@mui/material/Typography';
import Drawer from '@components/common/drawer/Drawer';
import { graphql, useLazyLoadQuery } from 'react-relay';
import Paper from '@mui/material/Paper';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import TableBody from '@mui/material/TableBody';
import { useTheme } from '@mui/styles';
import Dialog from '@mui/material/Dialog';
import DialogTitle from '@mui/material/DialogTitle';
import DialogContent from '@mui/material/DialogContent';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Tooltip from '@mui/material/Tooltip';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import Loader from '../../../../components/Loader';
import { HistoryDrawerQuery } from './__generated__/HistoryDrawerQuery.graphql';
import Transition from '../../../../components/Transition';
import useAuth from '../../../../utils/hooks/useAuth';

interface HistoryDrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  logId?: string;
}

const historyDrawerQuery = graphql`
  query HistoryDrawerQuery($id: ID!, $tz: String, $locale: String, $unit_system: String) {
    log(id: $id) {
      id
      context_data(tz: $tz, locale: $locale, unit_system: $unit_system) {
        entity_type
        message
        changes {
          field
          changes_added {
            raw
            human
          }
          changes_removed {
            raw
            human
          }
        }
      }
    }
  }
`;

const TruncatedRawValue: FunctionComponent<{ value: string }> = ({ value }) => {
  const { t_i18n } = useFormatter();
  const [open, setOpen] = useState(false);
  const theme = useTheme<Theme>();

  if (!value) return <pre style={{ margin: 0 }}>-</pre>;
  if (value.length <= 50) {
    return (
      <pre style={{
        fontFamily: 'Consolas, monaco, monospace',
        margin: 0,
        color: theme.palette.text?.secondary,
      }}
      >
        {value}
      </pre>
    );
  }

  return (
    <>
      <Tooltip title={t_i18n('Click to view full value')}>
        <pre
          onClick={() => setOpen(true)}
          style={{
            fontFamily: 'Consolas, monaco, monospace',
            cursor: 'pointer',
            margin: 0,
            color: theme.palette.text?.secondary,
          }}
        >
          {value.substring(0, 50)}...
        </pre>
      </Tooltip>
      <Dialog
        open={open}
        onClose={() => setOpen(false)}
        TransitionComponent={Transition}
        maxWidth="md"
        fullWidth={true}
      >
        <DialogTitle>{t_i18n('Raw value')}</DialogTitle>
        <DialogContent>
          <pre>{value}</pre>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)} color="primary">
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </>
  );
};

interface HistoryDrawerContentProps {
  logId: string;
}

const HistoryDrawerContent: FunctionComponent<HistoryDrawerContentProps> = ({ logId }) => {
  const { locale, tz, unitSystem } = useAuth();
  const variables = { id: logId, tz, locale: locale, unit_system: unitSystem };
  const data = useLazyLoadQuery<HistoryDrawerQuery>(historyDrawerQuery, variables);
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const changes = data?.log?.context_data?.changes;

  return (
    <div>
      <Paper variant="outlined" style={{ padding: 15, backgroundColor: theme.palette.background.paper, borderColor: theme.palette.primary.main }}>
        <Typography variant="h4" gutterBottom={true} color="primary">
          {t_i18n('Message')}
        </Typography>
        <MarkdownDisplay
          content={data?.log?.context_data?.message ?? ''}
          remarkGfmPlugin={true}
          commonmark={true}
        />
      </Paper>
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
                                  <pre style={{ margin: 0, color: theme.palette.text?.secondary }}>
                                    <TruncatedRawValue value={s.raw} />
                                  </pre>
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
                                  <pre style={{ margin: 0, color: theme.palette.text?.secondary }}>
                                    <TruncatedRawValue value={s.raw} />
                                  </pre>
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
    </div>
  );
};

const HistoryDrawer: FunctionComponent<HistoryDrawerProps> = ({ open, onClose, title, logId }) => {
  return logId
    ? (
        <Drawer open={open} onClose={onClose} title={title}>
          <Suspense fallback={<Loader />}>
            <HistoryDrawerContent logId={logId} />
          </Suspense>
        </Drawer>
      ) : <></>;
};

export default HistoryDrawer;
