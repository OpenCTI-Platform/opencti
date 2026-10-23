import React from 'react';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
// fds:keep-mui moved unchanged from DataTableToolBar.jsx by the toolbar refactoring, the conversion is left to the design-system migration
import Chip from '@mui/material/Chip';
import DialogActions from '@mui/material/DialogActions';
import Table from '@mui/material/Table';
import TableBody from '@mui/material/TableBody';
import TableCell from '@mui/material/TableCell';
import TableContainer from '@mui/material/TableContainer';
import TableHead from '@mui/material/TableHead';
import TableRow from '@mui/material/TableRow';
import Typography from '@mui/material/Typography';
import { useTheme } from '@mui/styles';
import { Chip as FdsChip } from '@filigran/design-system';
import Button from '@common/button/Button';
import Dialog from '@common/dialog/Dialog';
import TasksFilterValueContainer from '../../../../components/TasksFilterValueContainer';
import { useFormatter } from '../../../../components/i18n';
import type { Theme } from '../../../../components/Theme';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';
import { truncate } from '../../../../utils/String';
import { displayActionValue, type ToolBarAction } from '../dataTableToolBarTask';

interface BackgroundTaskDialogProps {
  open: boolean;
  onClose: () => void;
  onLaunch: () => void;
  processing: boolean;
  numberOfSelectedElements: number;
  // The scope of the task: the selected elements, or every element matching the search and filters
  selectAll: boolean;
  search?: string | null;
  filters?: FilterGroup | null;
  entityTypes: string[];
  selectedElementsList: unknown[];
  // The element kept by a merge, the only one the task targets
  mergingElement?: unknown;
  actions: ToolBarAction[];
  customFieldDefinitions: readonly { name: string; label: string }[];
}

// The confirmation of a background task launched from the toolbar, listing its scope and its steps
const BackgroundTaskDialog = ({
  open,
  onClose,
  onLaunch,
  processing,
  numberOfSelectedElements,
  selectAll,
  search,
  filters,
  entityTypes,
  selectedElementsList,
  mergingElement,
  actions,
  customFieldDefinitions,
}: BackgroundTaskDialogProps) => {
  const { t_i18n, n } = useFormatter();
  const theme = useTheme<Theme>();

  const stepNumber = (number: number) => (
    <span
      style={{
        padding: '2px 5px 2px 5px',
        marginRight: 5,
        color: theme.palette.mode === 'dark' ? '#000000' : '#ffffff',
        backgroundColor: theme.palette.primary.main,
      }}
    >
      {number}
    </span>
  );

  return (
    <Dialog
      open={open}
      onClose={onClose}
      data-testid="background-task-popup"
      title={(
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', width: '100%' }}>
          <span>{t_i18n('Launch a background task')}</span>
          <Typography variant="body1" color="textSecondary">
            {`${n(numberOfSelectedElements)} ${t_i18n('selected element(s)')}`}
          </Typography>
        </Box>
      )}
    >
      {numberOfSelectedElements > 1000 && (
        <Alert severity="warning">
          {t_i18n('You\'re targeting more than 1000 entities with this background task, be sure of what you\'re doing!')}
        </Alert>
      )}
      <TableContainer>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>#</TableCell>
              <TableCell>{t_i18n('Step')}</TableCell>
              <TableCell>{t_i18n('Field')}</TableCell>
              <TableCell>{t_i18n('Values')}</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            <TableRow>
              <TableCell>
                {' '}
                {stepNumber(1)}
              </TableCell>
              <TableCell>
                <FdsChip label="SCOPE" />
              </TableCell>
              <TableCell>{t_i18n('N/A')}</TableCell>
              <TableCell>
                {selectAll ? (
                  <div>
                    {search && search.length > 0 && (
                      <span>
                        <Chip
                          sx={{ margin: '5px 10px 5px 0' }}
                          label={(
                            <div>
                              <strong>{t_i18n('Search')}</strong>: {search}
                            </div>
                          )}
                        />
                        {(filters?.filters ?? []).length > 0 && (
                          <FdsChip label={t_i18n('AND')} />
                        )}
                      </span>
                    )}
                    <TasksFilterValueContainer filters={filters} entityTypes={entityTypes} />
                  </div>
                ) : (
                  <span>
                    {mergingElement
                      ? truncate(getMainRepresentative(mergingElement), 80)
                      : truncate(selectedElementsList.map((o) => getMainRepresentative(o)).join(', '), 80)}
                  </span>
                )}
              </TableCell>
            </TableRow>
            {actions.map((action, index) => (
              <TableRow key={action.type}>
                <TableCell>
                  {' '}
                  {stepNumber(index + 2)}
                </TableCell>
                <TableCell>
                  <FdsChip label={action.type} />
                </TableCell>
                <TableCell>
                  {customFieldDefinitions.find((d) => d.name === action.context?.field)?.label
                    ?? action.context?.field
                    ?? t_i18n('N/A')}
                </TableCell>
                <TableCell>
                  {truncate((action.context?.values ?? []).map(displayActionValue).join(', '), 80)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>
      <DialogActions>
        <Button variant="secondary" onClick={onClose} disabled={processing}>
          {t_i18n('Cancel')}
        </Button>
        <Button onClick={onLaunch} disabled={processing}>
          {t_i18n('Launch')}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default BackgroundTaskDialog;
