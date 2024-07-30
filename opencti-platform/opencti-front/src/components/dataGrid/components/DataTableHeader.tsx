import React, { FunctionComponent } from 'react';
import { ArrowDropDown, ArrowDropUp } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import SimpleDraggrable from 'react-draggable';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import { Theme as MuiTheme } from '@mui/material/styles/createTheme';
import { UnfoldMoreIcon } from 'filigran-icon';
import Tooltip from '@mui/material/Tooltip';
import { useDataTableContext } from '../dataTableUtils';
import { DataTableColumn, DataTableHeaderProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';

export const SELECT_COLUMN_SIZE = 42;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<MuiTheme, { column: DataTableColumn }>((theme) => createStyles({
  headerContainer: {
    position: 'relative',
    display: 'flex',
    width: ({ column }) => `calc(var(--header-${column?.id}-size) * 1px)`,
    fontWeight: 'bold',
    justifyContent: 'center',
    alignItems: 'center',
    height: 40,
    '& .react-draggable-dragging': {
      background: theme.palette.secondary.main,
    },
    '&:hover': {
      '& $draggable': {
        background: theme.palette.secondary.main,
      },
    },
  },
  headerAligner: {
    paddingLeft: 8,
    paddingRight: 8,
    display: 'flex',
    alignItems: 'center',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    cursor: ({ column: { isSortable } }) => (isSortable ? 'pointer' : 'unset'),
  },
  aligner: { flexGrow: 1 },
  draggable: {
    position: 'absolute',
    top: 0,
    right: 3,
    height: '100%',
    width: 4,
    borderRadius: 2,
    cursor: 'col-resize',
    userSelect: 'none',
    touchAction: 'none',
    zIndex: 999,
  },
}));

const DataTableHeader: FunctionComponent<DataTableHeaderProps> = ({
  column,
  setAnchorEl,
  setActiveColumn,
  setLocalStorageColumns,
  containerRef,
  sortBy,
  orderAsc,
}) => {
  const classes = useStyles({ column });

  const {
    columns,
    setColumns,
    availableFilterKeys,
    onSort,
    variant,
    formatter: { t_i18n },
  } = useDataTableContext();

  return (
    <div
      key={column.id}
      className={classes.headerContainer}
    >
      <div
        className={classes.headerAligner}
        onClick={(e) => {
          // Small debounce
          (e.target as HTMLDivElement).style.setProperty('pointer-events', 'none');
          setTimeout(() => {
            (e.target as HTMLDivElement).style.setProperty('pointer-events', 'auto');
          }, 800);
          if (column.isSortable) {
            onSort(column.id, !orderAsc);
          }
        }}
      >
        <Tooltip title={t_i18n(column.label)}>{t_i18n(column.label)}</Tooltip>
        {sortBy && (orderAsc ? <ArrowDropUp /> : <ArrowDropDown />)}
      </div>
      <>
        {(column.isSortable || (availableFilterKeys ?? []).includes(column.id)) && (
          <>
            <IconButton
              disableRipple
              onClick={(e) => {
                setActiveColumn(column);
                setAnchorEl(e.currentTarget);
              }}
              sx={{
                marginRight: 1,
                opacity: 0.5,
                width: 24,
                '&:hover': {
                  background: 'transparent',
                },
              }}
            >
              <UnfoldMoreIcon />
            </IconButton>
          </>
        )}
        <div className={classes.aligner} />
        {variant !== DataTableVariant.inline && (
          <SimpleDraggrable
            position={{ x: 3, y: 0 }}
            axis="x"
            onStop={(e, { lastX }) => {
              const eventTarget = (e?.target as HTMLDivElement);
              const currentClasses = classes.headerContainer.split(' ');
              if (!containerRef || !(currentClasses.some((c) => eventTarget?.classList.contains(c)) || eventTarget?.classList.contains('react-draggable-dragging'))) {
                return;
              }
              const newSize = (column?.size ?? 0) + lastX;

              const effectiveColumns = columns.filter(({ id }) => !['select', 'navigate'].includes(id));
              const currentSize = effectiveColumns.reduce((acc, col) => acc + (col.size ?? 0), 0);

              const currentColIndex = effectiveColumns.findIndex(({ id }) => id === column.id);
              const otherColIndex = currentColIndex === effectiveColumns.length - 1 ? currentColIndex - 1 : currentColIndex + 1;
              const currentCol = effectiveColumns[currentColIndex];

              currentCol.size = newSize;

              const startsWithSelect = columns.at(0)?.id === 'select';
              const endsWithNavigate = columns.at(-1)?.id === 'navigate';
              let storedSize = SELECT_COLUMN_SIZE;
              if (startsWithSelect) {
                storedSize += SELECT_COLUMN_SIZE;
              }

              const clientWidth = (containerRef.current?.clientWidth ?? 0) - storedSize - 10; // Scrollbar size to prevent alignment issues

              const otherColumn = effectiveColumns[otherColIndex];
              const clientDiff = clientWidth - effectiveColumns.reduce((acc, col) => acc + (col.size ?? 0), 0);

              if (clientDiff > 0) {
                const percentWidth = (100 * currentCol.size) / currentSize;
                if (otherColumn) {
                  const otherColumnNewSize = (otherColumn.size ?? 0) - lastX - currentSize + clientWidth;
                  otherColumn.size = otherColumnNewSize;
                  otherColumn.percentWidth = (otherColumnNewSize * 100) / clientWidth;
                }
                currentCol.percentWidth = percentWidth;
              }

              setLocalStorageColumns((curr: LocalStorageColumns) => ({
                ...curr,
                [column.id]: { ...curr[column.id], size: newSize },
                [otherColumn.id]: { ...curr[otherColumn.id], ...otherColumn },
              }));
              const newColumns = [
                ...(startsWithSelect ? [columns.at(0) as DataTableColumn] : []),
                ...effectiveColumns,
                ...(endsWithNavigate ? [columns.at(-1) as DataTableColumn] : [])];
              setColumns(newColumns);
            }}
          >
            <div
              className={classes.draggable}
            />
          </SimpleDraggrable>
        )}
      </>
    </div>
  );
};

export default DataTableHeader;
