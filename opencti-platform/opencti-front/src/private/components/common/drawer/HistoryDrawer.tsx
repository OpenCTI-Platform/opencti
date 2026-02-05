import { FunctionComponent } from 'react';
import Drawer from '@components/common/drawer/Drawer';
import { useFragment } from 'react-relay';
import { StixCoreObjectHistoryFragment } from '@components/common/stix_core_objects/StixCoreObjectHistoryLine';
import { StixCoreObjectHistoryLine_node$key } from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLine_node.graphql';
import TableContainer from '@mui/material/TableContainer';
import Table from '@mui/material/Table';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import TableCell from '@mui/material/TableCell';
import TableBody from '@mui/material/TableBody';
import MarkdownDisplay from '../../../../components/MarkdownDisplay';
import { useFormatter } from '../../../../components/i18n';
import { StixCoreRelationshipHistoryFragment } from '@components/common/stix_core_relationships/StixCoreRelationshipHistoryLine';
import Label from '../../../../components/common/label/Label';
import Card from '../../../../components/common/card/Card';
import { EMPTY_VALUE } from '../../../../utils/String';

interface HistoryDrawerProps {
  open: boolean;
  onClose: () => void;
  title: string;
  node: StixCoreObjectHistoryLine_node$key | undefined;
  isRelation: boolean;
}

const HistoryDrawer: FunctionComponent<HistoryDrawerProps> = ({ open, onClose, title, node, isRelation }) => {
  const drawerFragment = isRelation
    ? StixCoreRelationshipHistoryFragment
    : StixCoreObjectHistoryFragment;
  const data = useFragment(drawerFragment, node);
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
          <Label>
            {t_i18n('Message')}
          </Label>
          <MarkdownDisplay
            content={data?.context_data?.message}
            remarkGfmPlugin={true}
            commonmark={true}
          />
        </div>
        <div style={{ marginTop: 16 }}>
          <Label>
            {t_i18n('Details')}
          </Label>
          <Card>
            <TableContainer>
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
                      <TableCell align="left">{row?.previous && row.previous.length > 0
                        ? row.previous.join(', ')
                        : EMPTY_VALUE}
                      </TableCell>
                      <TableCell align="left">{row?.new && row.new.length > 0
                        ? row.new.join(', ')
                        : EMPTY_VALUE}
                      </TableCell>
                      <TableCell align="left">{row?.added && row.added.length > 0
                        ? row.added.join(', ')
                        : EMPTY_VALUE}
                      </TableCell>
                      <TableCell align="left">{row?.removed && row.removed.length > 0
                        ? row.removed.join(', ')
                        : EMPTY_VALUE}
                      </TableCell>
                    </TableRow>
                  ))
                  ) : (
                    <TableRow>
                      <TableCell align="center" colSpan={5}>
                        {t_i18n('No detail available for this event')}
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </TableContainer>
          </Card>
        </div>
      </div>
    </Drawer>
  );
};
export default HistoryDrawer;
