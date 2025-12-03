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
import { useFormatter } from '../../../../components/i18n';
import { StixCoreRelationshipHistoryFragment } from '@components/common/stix_core_relationships/StixCoreRelationshipHistoryLine';

interface HistoryDrawerProps {
  open: boolean
  onClose: () => void
  title: string
  node: StixCoreObjectHistoryLine_node$key | undefined
  isRelation: boolean
}

const HistoryDrawer: FunctionComponent<HistoryDrawerProps> = ({ open, onClose, title, node, isRelation }) => {
  const drawerFragment = isRelation ?
    StixCoreRelationshipHistoryFragment
    : StixCoreObjectHistoryFragment;
  const data = useFragment(drawerFragment, node);
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
  const changes = data?.context_data?.changes;

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title={title}
    >
      <div>
        <div>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Message')}
          </Typography>
          <MarkdownDisplay
            content={data?.context_data?.message ?? ''}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </div>
        <div style={{ marginTop: 16 }}>
          <Typography variant="h4" gutterBottom={true}>
            {t_i18n('Details')}
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

                <TableContainer component={Paper}>
                  <Table sx={{ minWidth: 650 }} size="small">
                    <TableHead>
                      <TableRow>
                        <TableCell></TableCell>
                        <TableCell align="left">{t_i18n('Previous value')}</TableCell>
                        <TableCell align="left">{t_i18n('New value')}</TableCell>
                        <TableCell align="left">{t_i18n('Added')}</TableCell>
                        <TableCell align="left">{t_i18n('Removed')}</TableCell>
                      </TableRow>
                    </TableHead>
                    <TableBody>
                      {changes && changes.length > 0 ? (changes.map((row) => (
                        <TableRow
                          key={row?.field}
                          sx={{ '&:last-child td, &:last-child th': { border: 0 } }}
                        >
                          <TableCell component="th" scope="row">
                            {row?.field}
                          </TableCell>
                          <TableCell align="left">{row?.previous ? JSON.stringify(row?.previous): '-'}</TableCell>
                          <TableCell align="left">{row?.new ? JSON.stringify(row?.new): '-'}</TableCell>
                          <TableCell align="left">{row?.added ? JSON.stringify(row?.added): '-'}</TableCell>
                          <TableCell align="left">{row?.removed ? JSON.stringify(row?.removed): '-'}</TableCell>
                        </TableRow>
                      ))
                        ) : (
                          <TableRow>
                            <TableCell align="center" colSpan={5}>
                              {t_i18n('No changes')}
                            </TableCell>
                          </TableRow>
                        )}
                    </TableBody>
                  </Table>
                </TableContainer>
              </div>
            </div>
          </Paper>
        </div>
      </div>
    </Drawer>
);
};
export default HistoryDrawer;
