import React, { FunctionComponent } from 'react';
import { ArrowDropDown, ArrowDropUp, MoreVert } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import SimpleDraggrable from 'react-draggable';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import { Theme as MuiTheme } from '@mui/material/styles/createTheme';
import Tooltip from '@mui/material/Tooltip';
import { DataTableColumn, DataTableHeaderProps, DataTableVariant, LocalStorageColumns } from '../dataTableTypes';
import { useDataTableContext } from './DataTableContext';

export const SELECT_COLUMN_SIZE = 42;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<MuiTheme, { column: DataTableColumn }>((theme) => createStyles({
  headerContainer: {
    position: 'relative',
    display: 'flex',
    width: ({ column }) => `calc(var(--header-${column?.id}-size) * 1px)`,
    fontWeight: 'bold',
    justifyContent: 'space-between',
    alignItems: 'center',
    '& .react-draggable-dragging': {
      backgroundColor: theme.palette.primary.main,
    },
    '&:hover': {
      '& $draggable': {
        backgroundColor: theme.palette.primary.main,
      },
      '& $icon': {
        visibility: 'visible',
      },
    },
  },
  headerAligner: {
    paddingLeft: theme.spacing(1),
    paddingRight: theme.spacing(1),
    display: 'flex',
    alignItems: 'center',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    flexGrow: 1,
    cursor: ({ column: { isSortable } }) => (isSortable ? 'pointer' : 'unset'),
  },
  draggable: {
    position: 'absolute',
    top: '8px',
    right: 3,
    height: theme.spacing(4),
    width: 10,
    paddingLeft: 4,
    paddingRight: 4,
    backgroundClip: 'content-box',
    borderRadius: 2,
    cursor: 'col-resize',
  },
  icon: {
    visibility: 'hidden',
  },
}));

const DataTableHeader: FunctionComponent<DataTableHeaderProps> = ({
  column,
  setAnchorEl,
  isActive,
  setActiveColumn,
  containerRef,
  sortBy,
  orderAsc,
}) => {
  const classes = useStyles({ column });

  const {
    columns,
    actions,
    availableFilterKeys,
    onSort,
    variant,
    formatter: { t_i18n },
    useDataTableColumnsLocalStorage,
  } = useDataTableContext();

  const [_, setLocalStorageColumns] = useDataTableColumnsLocalStorage;

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
        <Tooltip title={t_i18n(column.label)}>
          <span style={{ fontSize: '12px' }}>{t_i18n(column.label).toUpperCase()}</span>
        </Tooltip>
        {sortBy && (orderAsc ? <ArrowDropUp /> : <ArrowDropDown />)}
      </div>
      <>
        {(column.isSortable || (availableFilterKeys ?? []).includes(column.id)) && (
          <>
            <IconButton
              disableRipple
              className={classes.icon}
              onClick={(e) => {
                setActiveColumn(column);
                setAnchorEl(e.currentTarget);
              }}
              style={{
                visibility: isActive ? 'visible' : undefined,
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
              <MoreVert />
            </IconButton>
          </>
        )}
        <div className={classes.aligner} />
        {variant !== DataTableVariant.inline && variant !== DataTableVariant.widget && (
          <SimpleDraggrable
            position={{ x: 3, y: 0 }}
            axis="x"
            onStop={(e, { lastX }) => {
              const newSize = (column?.size ?? 0) + lastX;

              const effectiveColumns = columns.filter(({ id }) => !['select', 'navigate'].includes(id));
              const currentSize = effectiveColumns.reduce((acc, col) => acc + (col.size ?? 0), 0);

              const currentColIndex = effectiveColumns.findIndex(({ id }) => id === column.id);
              const otherColIndex = currentColIndex === effectiveColumns.length - 1 ? currentColIndex - 1 : currentColIndex + 1;
              const currentCol = effectiveColumns[currentColIndex];

              currentCol.size = newSize;

              const startsWithSelect = columns.at(0)?.id === 'select';
              const endsWithTechnical = columns.at(-1)?.id === 'navigate' || actions;
              let storedSize = endsWithTechnical ? SELECT_COLUMN_SIZE : 0;
              if (startsWithSelect) {
                storedSize += SELECT_COLUMN_SIZE;
              }

              const clientWidth = (containerRef?.current?.clientWidth ?? 0) - storedSize - 12; // Scrollbar size to prevent alignment issues

              const otherColumn = effectiveColumns[otherColIndex];
              const clientDiff = clientWidth - effectiveColumns.reduce((acc, col) => acc + (col.size ?? 0), 0);

              if (clientDiff > 0) {
                if (otherColumn) {
                  otherColumn.size = (otherColumn.size ?? 0) - lastX - currentSize + clientWidth;
                }
              }

              setLocalStorageColumns((curr: LocalStorageColumns) => ({
                ...curr,
                [column.id]: { ...curr[column.id], size: newSize },
                [otherColumn.id]: { ...curr[otherColumn.id], ...otherColumn },
              }));
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
