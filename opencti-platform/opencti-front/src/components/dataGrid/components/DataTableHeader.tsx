import React, { FunctionComponent, MouseEvent, RefObject, useRef } from 'react';
import { ArrowDropDown, ArrowDropUp, MoreVert } from '@mui/icons-material';
import IconButton from '@mui/material/IconButton';
import SimpleDraggrable from 'react-draggable';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import { Theme as MuiTheme } from '@mui/material/styles/createTheme';
import Tooltip from '@mui/material/Tooltip';
import { DataTableColumn, DataTableHeaderProps, DataTableVariant } from '../dataTableTypes';
import { useDataTableContext } from './DataTableContext';

export const SELECT_COLUMN_SIZE = 42;
export const ICON_COLUMN_SIZE = 56;

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<MuiTheme, { column: DataTableColumn }>((theme) => createStyles({
  headerContainer: {
    flex: '0 0 auto',
    position: 'relative',
    display: 'flex',
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
  label: {
    paddingLeft: theme.spacing(1),
    paddingRight: theme.spacing(1),
    display: 'flex',
    alignItems: 'center',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    fontSize: '12px',
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
  const draggableRef = useRef<HTMLDivElement>(null);
  const classes = useStyles({ column });

  const {
    columns,
    setColumns,
    availableFilterKeys,
    onSort,
    variant,
    formatter: { t_i18n },
    tableWidthState: [tableWidth],
  } = useDataTableContext();

  // To avoid spamming sorting (and calling API)
  const throttleSortColumn = (e: MouseEvent) => {
    const el = e.target as HTMLDivElement;
    el.style.setProperty('pointer-events', 'none');
    setTimeout(() => el.style.setProperty('pointer-events', 'auto'), 800);
    if (column.isSortable) onSort(column.id, !orderAsc);
  };

  const openColumnMenu = (e: MouseEvent) => {
    setActiveColumn(column);
    setAnchorEl(e.currentTarget);
  };

  const hasColumnMenu = column.isSortable || (availableFilterKeys ?? []).includes(column.id);
  const cellWidth = Math.round(tableWidth * (column.percentWidth / 100));

  return (
    <div
      key={column.id}
      className={classes.headerContainer}
      style={{ width: cellWidth }}
    >
      <div className={classes.label} onClick={throttleSortColumn}>
        <Tooltip title={t_i18n(column.label)}>
          <span>{t_i18n(column.label)}</span>
        </Tooltip>
        {sortBy && (orderAsc ? <ArrowDropUp /> : <ArrowDropDown />)}
      </div>

      {hasColumnMenu && (
        <IconButton
          disableRipple
          className={classes.icon}
          onClick={openColumnMenu}
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
      )}

      <div className={classes.aligner} />

      {variant !== DataTableVariant.inline && variant !== DataTableVariant.widget && (
        <SimpleDraggrable
          nodeRef={draggableRef as unknown as RefObject<HTMLDivElement>}
          position={{ x: 3, y: -3 }}
          axis="x"
          onStop={(_, { lastX }) => {
            if (containerRef?.current) {
              // Compute new width in percentage of the column.
              const containerWidth = containerRef.current.clientWidth;
              const columnWidth = (column.percentWidth * containerWidth) / 100;
              const newColumnWidth = columnWidth + lastX;
              const newPercentage = (newColumnWidth / containerWidth) * 100;
              if (newPercentage < 0) return;

              // Override the new percent width.
              let newColumns = columns.map((c) => {
                if (c.id === column.id) return { ...c, percentWidth: newPercentage };
                return c;
              });

              // Total width should be at least 100% so extend neighbor column if necessary.
              const sumPercentage = newColumns.reduce((acc, col) => acc + (col.percentWidth ?? 0), 0);
              if (sumPercentage < 100) {
                const maxOrder = Math.max(...newColumns.flatMap((c) => c.order ?? []));
                const neighborOrder = column.order < maxOrder ? column.order + 1 : column.order - 1;
                newColumns = newColumns.map((c) => {
                  if (c.order === neighborOrder) {
                    const percentWidth = c.percentWidth + (100 - sumPercentage);
                    return { ...c, percentWidth };
                  }
                  return c;
                });
              }

              setColumns(newColumns);
            }
          }}
        >
          <div ref={draggableRef} className={classes.draggable} />
        </SimpleDraggrable>
      )}
    </div>
  );
};

export default DataTableHeader;
