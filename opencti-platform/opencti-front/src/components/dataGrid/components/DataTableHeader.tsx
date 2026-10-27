import React, { FunctionComponent, MouseEvent, RefObject, useRef } from 'react';
import { ArrowDropDown, ArrowDropUp, MoreVert } from '@mui/icons-material';
import IconButton from '@common/button/IconButton';
import SimpleDraggable from 'react-draggable';
import { styled } from '@mui/material/styles';
import Tooltip from '@mui/material/Tooltip';
import { DataTableHeaderProps, DataTableVariant } from '../dataTableTypes';
import { useDataTableContext } from './DataTableContext';

export const SELECT_COLUMN_SIZE = 42;
export const ICON_COLUMN_SIZE = 56;

// Marks the column menu button whichever way @common/button renders it: design-system button or MUI fallback.
const COLUMN_MENU_BUTTON_CLASS = 'DataTableHeader-columnMenu';

const HeaderContainer = styled('div')(({ theme }) => ({
  flex: '0 0 auto',
  position: 'relative',
  display: 'flex',
  fontWeight: 'bold',
  justifyContent: 'space-between',
  alignItems: 'center',
  '& .react-draggable-dragging': {
    backgroundColor: theme.palette.primary.main,
  },
  [`& .${COLUMN_MENU_BUTTON_CLASS}`]: {
    visibility: 'hidden',
  },
  '&:hover': {
    '& .react-draggable': {
      backgroundColor: theme.palette.primary.main,
    },
    [`& .${COLUMN_MENU_BUTTON_CLASS}`]: {
      visibility: 'visible',
    },
  },
}));

const Label = styled('button', {
  shouldForwardProp: (prop) => prop !== 'sortable',
})<{ sortable?: boolean }>(({ theme, sortable }) => ({
  background: 'none',
  border: 'none',
  color: theme.palette.text.primary,
  fontWeight: 700,
  paddingLeft: theme.spacing(1),
  paddingRight: theme.spacing(1),
  display: 'flex',
  alignItems: 'center',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  fontSize: '12px',
  width: '100%',
  cursor: sortable ? 'pointer' : 'unset',
}));

const Draggable = styled('div')(({ theme }) => ({
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

  const {
    columns,
    setColumns,
    availableFilterKeys,
    onSort,
    disableColumnMenu,
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

  const hasColumnMenu = !disableColumnMenu && (column.isSortable || (availableFilterKeys ?? []).includes(column.id));
  const cellWidth = Math.round(tableWidth * (column.percentWidth / 100));

  return (
    <HeaderContainer
      key={column.id}
      style={{ width: cellWidth }}
    >
      <div style={{ overflow: 'hidden', flex: 1 }} role="columnheader" aria-sort={sortBy ? (orderAsc ? 'ascending' : 'descending') : 'none'}>
        <Label type="button" sortable={column.isSortable} onClick={throttleSortColumn} disabled={!column.isSortable}>
          <Tooltip title={t_i18n(column.label)}>
            <span>{t_i18n(column.label)}</span>
          </Tooltip>
          {sortBy && column.isSortable && (orderAsc ? <ArrowDropUp /> : <ArrowDropDown />)}
        </Label>
      </div>
      {hasColumnMenu && (
        <IconButton
          disableRipple
          aria-label={t_i18n('View more')}
          className={COLUMN_MENU_BUTTON_CLASS}
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

      <div />

      {variant !== DataTableVariant.inline && variant !== DataTableVariant.widget && (
        <SimpleDraggable
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
          <Draggable ref={draggableRef} />
        </SimpleDraggable>
      )}
    </HeaderContainer>
  );
};

export default DataTableHeader;
