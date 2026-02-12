import React, { FunctionComponent } from 'react';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Paper from '@mui/material/Paper';
import { useFormatter } from '../../i18n';
import TruncatedRawValue from '../../../private/components/common/drawer/TruncatedRawValue';

export interface Change {
  field?: string;
  removed: readonly string[];
  added: readonly string[];
}

interface ChangesTableProps {
  changes: readonly Change[];
  variant?: 'code' | 'text';
}

const ChangesTable: FunctionComponent<ChangesTableProps> = ({ changes, variant = 'code' }) => {
  const { t_i18n } = useFormatter();

  const renderChangeValues = (values?: readonly string[] | null) => {
    if (!values || values.length === 0) {
      return <TruncatedRawValue value="-" variant={variant} />;
    }
    return values.map((s, i) => (
      <div key={i} style={{ marginBottom: i < values.length - 1 ? 8 : 0 }}>
        <TruncatedRawValue value={s} variant={variant} />
      </div>
    ));
  };

  return (
    <TableContainer component={Paper} variant="outlined" sx={{ border: 'none' }}>
      <Table
        size="small"
        aria-label="changes list"
        sx={{
          tableLayout: 'fixed',
          '& .MuiTableRow-root:last-child .MuiTableCell-root': {
            borderBottom: 'none',
          },
        }}
      >
        <TableHead>
          <TableRow>
            <TableCell sx={{ fontSize: 12, fontWeight: 'bold' }}>{t_i18n('Field').toUpperCase()}</TableCell>
            <TableCell width="40%" sx={{ fontSize: 12, fontWeight: 'bold' }}>{t_i18n('Removed').toUpperCase()}</TableCell>
            <TableCell width="40%" sx={{ fontSize: 12, fontWeight: 'bold' }}>{t_i18n('Added').toUpperCase()}</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {changes && changes.length > 0
            ? changes.map((row) => (
                <TableRow key={row?.field} hover={false}>
                  <TableCell component="th" scope="row" sx={{ fontWeight: 'bold', padding: '14px' }}>
                    {row?.field}
                  </TableCell>
                  <TableCell>{renderChangeValues(row?.removed)}</TableCell>
                  <TableCell>{renderChangeValues(row?.added)}</TableCell>
                </TableRow>
              ))
            : (
                <TableRow>
                  <TableCell align="center" colSpan={3} sx={{ height: 50 }}>
                    {t_i18n('No detail available for this event')}
                  </TableCell>
                </TableRow>
              )}
        </TableBody>
      </Table>
    </TableContainer>
  );
};

export default ChangesTable;
