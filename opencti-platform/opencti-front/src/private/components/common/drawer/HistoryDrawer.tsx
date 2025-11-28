import React, { FunctionComponent } from 'react';
import Typography from '@mui/material/Typography';
import Drawer from '@components/common/drawer/Drawer';
import { useFragment } from 'react-relay';
import { StixCoreObjectHistoryFragment } from '@components/common/stix_core_objects/StixCoreObjectHistoryLine';
import { StixCoreObjectHistoryLine_node$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLine_node.graphql';
import Paper from '@mui/material/Paper';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import TableBody from '@mui/material/TableBody';
import { useTheme } from '@mui/styles';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from "../../../../components/i18n";

interface HistoryDrawerProps {
  open: boolean
  onClose: () => void
  title: string
  node: StixCoreObjectHistoryLine_node$key | undefined
}

const HistoryDrawer: FunctionComponent<HistoryDrawerProps> = ({ open, onClose, title, node }) => {
  const data = useFragment(StixCoreObjectHistoryFragment, node);
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={title}
    >
      <div>
        <div>
          <Typography variant="h4" gutterBottom={true}>
            {('Message')}
          </Typography>
          <MarkdownDisplay
            content={data?.context_data?.message ?? ''}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </div>
        <div style={{ marginTop: 16 }}>
          <Typography variant="h4" gutterBottom={true}>
            {('Details')}
          </Typography>
          <Paper style={{ marginTop: theme.spacing(1), position: 'relative' }}>
            <div style={{ height: '100%', width: '100%' }}>
              <div style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100%',
                textAlign: 'center',
              }}
              >
                {data?.context_data?.changes && data.context_data.changes.length > 0 ? (
                <TableContainer component={Paper}>
                  <Table sx={{ minWidth: 650 }} size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell></TableCell>
                        <TableCell align="left">Previous value</TableCell>
                        <TableCell align="left">New value</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {data?.context_data?.changes.map((row) => (
                        <TableRow
                          key={row?.field}
                          sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                        >
                          <TableCell component="th" scope="row">
                            {row?.field}
                          </TableCell>
                          <TableCell align="left">{row?.previous}</TableCell>
                          <TableCell align="left">{row?.new}</TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </TableContainer>
                ) : (
                  <div>
                    {t_i18n('No detail in this log')}
                  </div>
                  )}
              </div>
            </div>
          </Paper>
        </div>
      </div>
    </Drawer>
);
};
export default HistoryDrawer;
