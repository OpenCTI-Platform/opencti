import React, { FunctionComponent } from 'react';
import { useLazyLoadQuery, graphql } from 'react-relay';
import Drawer from '@components/common/drawer/Drawer';
import Dialog from '@mui/material/Dialog';
import DialogContent from '@mui/material/DialogContent';
import DialogContentText from '@mui/material/DialogContentText';
import DialogActions from '@mui/material/DialogActions';
import Button from '@mui/material/Button';
import Paper from '@mui/material/Paper';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import TableBody from '@mui/material/TableBody';
import { CheckCircle, Cancel } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import type { IngestionHistoryDrawerQuery } from './__generated__/IngestionHistoryDrawerQuery.graphql';
import Loader from '../../../../components/Loader';

const ingestionHistoryDrawerQuery = graphql`
  query IngestionHistoryDrawerQuery($id: String!) {
    ingestionHistory(id: $id) {
      timestamp
      status
      messages
      count
    }
  }
`;

interface IngestionHistoryDrawerProps {
  open: boolean;
  onClose: () => void;
  ingestionId: string | null;
}

const IngestionHistoryDrawerContent: FunctionComponent<{ ingestionId: string }> = ({ ingestionId }) => {
  const { t_i18n, fldt } = useFormatter();
  const theme = useTheme<Theme>();
  const data = useLazyLoadQuery<IngestionHistoryDrawerQuery>(ingestionHistoryDrawerQuery, { id: ingestionId }, { fetchPolicy: 'network-only' });
  const [openDialog, setOpenDialog] = React.useState(false);
  const [dialogContent, setDialogContent] = React.useState<string | null>(null);

  const handleOpenDialog = (content: string) => {
    setOpenDialog(true);
    setDialogContent(content);
  };

  const handleCloseDialog = () => {
    setOpenDialog(false);
    setDialogContent(null);
  };

  const history = data.ingestionHistory ?? [];

  return (
    <TableContainer component={Paper} variant="outlined" style={{ marginTop: 20 }}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell width={240}>{t_i18n('Date')}</TableCell>
            <TableCell width={100}>{t_i18n('Status')}</TableCell>
            <TableCell width={80}>{t_i18n('Count')}</TableCell>
            <TableCell>{t_i18n('Message')}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {history.map((entry, index) => {
            if (!entry) {
              return null;
            }
            const status = entry.status ?? 'unknown';
            const fullMessage = (entry.messages ?? []).join('\n');
            const firstLine = fullMessage.split('\n')[0] ?? '';
            const truncatedMessage = firstLine.length > 150 ? `${firstLine.substring(0, 150)}...` : firstLine;
            const hasMore = fullMessage.length > firstLine.length || firstLine.length > 150;

            return (
              <TableRow key={index} hover={true}>
                <TableCell>{entry.timestamp ? fldt(entry.timestamp) : '-'}</TableCell>
                <TableCell>
                  {status === 'error' ? (
                    <Cancel style={{ color: theme.palette.error.main }} />
                  ) : (
                    <CheckCircle style={{ color: theme.palette.success.main }} />
                  )}
                </TableCell>
                <TableCell>{entry.count ?? 0}</TableCell>
                <TableCell
                  onClick={hasMore ? () => handleOpenDialog(fullMessage) : undefined}
                  style={{ cursor: hasMore ? 'pointer' : 'auto' }}
                >
                  {truncatedMessage}
                </TableCell>
              </TableRow>
            );
          })}
          {history.length === 0 && (
            <TableRow>
              <TableCell colSpan={4} style={{ textAlign: 'center' }}>
                {t_i18n('No history data available')}
              </TableCell>
            </TableRow>
          )}
        </TableBody>
      </Table>
      <Dialog
        PaperProps={{ elevation: 1 }}
        open={openDialog}
        onClose={handleCloseDialog}
        fullWidth={true}
        maxWidth="md"
      >
        <DialogContent>
          <DialogContentText style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {dialogContent}
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCloseDialog}>
            {t_i18n('Close')}
          </Button>
        </DialogActions>
      </Dialog>
    </TableContainer>
  );
};

const IngestionHistoryDrawer: FunctionComponent<IngestionHistoryDrawerProps> = ({ open, onClose, ingestionId }) => {
  const { t_i18n } = useFormatter();
  return (
    <Drawer open={open} onClose={onClose} title={t_i18n('Ingestion History (last 20)')}>
      <React.Suspense fallback={<Loader />}>
        {ingestionId ? <IngestionHistoryDrawerContent ingestionId={ingestionId} /> : null}
      </React.Suspense>
    </Drawer>
  );
};

export default IngestionHistoryDrawer;
