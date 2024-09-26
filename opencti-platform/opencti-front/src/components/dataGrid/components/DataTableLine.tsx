import React, { useMemo } from 'react';
import Skeleton from '@mui/material/Skeleton';
import Checkbox from '@mui/material/Checkbox';
import IconButton from '@mui/material/IconButton';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import { useDataTableContext } from '../dataTableUtils';
import type { DataTableCellProps, DataTableLineProps } from '../dataTableTypes';
import { DataTableColumn, DataTableVariant } from '../dataTableTypes';
import type { Theme } from '../../Theme';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme, { cell?: DataTableColumn, clickable?: boolean }>((theme) => createStyles({
  cellContainer: ({ cell }) => ({
    display: 'flex',
    width: `calc(var(--col-${cell?.id}-size) * 1px)`,
    height: theme.spacing(6),
    alignItems: 'center',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
  }),
  cellPadding: {
    display: 'flex',
    paddingLeft: theme.spacing(1),
    paddingRight: theme.spacing(1),
    width: 'fill-available',
    alignItems: 'center',
    gap: 3,
    fontSize: '13px',
  },
  dummyContainer: {
    height: theme.spacing(6),
    alignItems: 'center',
    display: 'flex',
    gap: 8,
  },
  row: ({ clickable }) => ({
    borderBottom: `1px solid ${theme.palette.divider}`,
    display: 'flex',
    '&:hover': clickable ? {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .1)'
          : 'rgba(0, 0, 0, .1)',
    } : {},
  }),
}));

export const DataTableLineDummy = () => {
  const classes = useStyles({});
  const { effectiveColumns } = useDataTableContext();

  const lines = useMemo(() => (
    <>
      {effectiveColumns.map((column) => (
        <Skeleton
          key={column.id}
          variant="text"
          height={35}
          style={{ width: `calc(var(--col-${column.id}-size) * 1px)` }}
        />
      ))}
    </>
  ), [effectiveColumns]);
  return (
    <div className={classes.dummyContainer}>
      {lines}
    </div>
  );
};

export const DataTableLinesDummy = ({ number = 10 }: { number?: number }) => {
  return Array(Math.min(number, 25)).fill(0).map((_, idx) => (<DataTableLineDummy key={idx} />));
};

const DataTableCell = ({
  cell,
  data,
}: DataTableCellProps) => {
  const classes = useStyles({ cell });
  const { useDataCellHelpers } = useDataTableContext();

  const helpers = useDataCellHelpers(cell);

  return (
    <div
      key={`${cell.id}_${data.id}`}
      className={classes.cellContainer}
    >
      <div className={classes.cellPadding}>
        {cell.render?.(data, helpers) ?? (<div>-</div>)}
      </div>
    </div>
  );
};

const DataTableLine = ({
  row,
  redirectionMode,
  storageHelpers,
  effectiveColumns,
  index,
  onToggleShiftEntity,
}: DataTableLineProps) => {
  const navigate = useNavigate();

  const {
    storageKey,
    useLineData,
    useDataTableToggle,
    useComputeLink,
    actions,
    disableNavigation,
    onLineClick,
    selectOnLineClick,
    variant,
  } = useDataTableContext();
  const data = useLineData(row);

  let link = useComputeLink(data);
  if (redirectionMode && redirectionMode !== 'overview') {
    link = `${link}/${redirectionMode}`;
  }

  const navigable = !disableNavigation && !onLineClick && !selectOnLineClick;
  const clickable = !!(navigable || selectOnLineClick || onLineClick);

  const classes = useStyles({ clickable });

  const {
    selectAll,
    deSelectedElements,
    selectedElements,
    onToggleEntity,
  } = useDataTableToggle(storageKey);

  const startsWithSelect = effectiveColumns.at(0)?.id === 'select';
  const endWithNavigate = effectiveColumns.at(-1)?.id === 'navigate';

  const handleSelectLine = (event: React.MouseEvent) => {
    if (event.shiftKey) {
      onToggleShiftEntity(index, data, event);
    } else {
      onToggleEntity(data, event);
    }
  };

  const handleNavigate = (event: React.MouseEvent) => {
    if (event.ctrlKey) {
      window.open(link, '_blank');
    } else {
      navigate(link);
    }
  };

  const handleRowClick = (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();

    if (selectOnLineClick) {
      handleSelectLine(event);
    } else if (onLineClick) {
      onLineClick(data);
    } else {
      handleNavigate(event);
    }
  };

  return (
    <div
      key={row.id}
      className={classes.row}
      style={{ cursor: clickable ? 'pointer' : 'unset' }}
      // We need both to handle accessibility and widget.
      onMouseDown={variant === DataTableVariant.widget ? handleNavigate : undefined}
      onClick={variant !== DataTableVariant.widget ? handleRowClick : undefined}
      data-testid={getMainRepresentative(data)}
    >
      <a
        style={{ display: 'flex', color: 'inherit' }}
        href={navigable ? link : undefined}
      >
        {startsWithSelect && (
          <div
            key={`select_${data.id}`}
            className={classes.cellContainer}
            style={{
              width: 'calc(var(--col-select-size) * 1px)',
            }}
          >

            <Checkbox
              onClick={handleSelectLine}
              sx={{
                marginRight: 1,
                width: 24,
                '&:hover': {
                  background: 'transparent',
                },
              }}
              checked={
                (selectAll
                  && !((data.id || 'id') in (deSelectedElements || {})))
                || (data.id || 'id') in (selectedElements || {})
              }
            />
          </div>
        )}
        {effectiveColumns.slice(startsWithSelect ? 1 : 0, (actions || disableNavigation) ? undefined : -1).map((column) => (
          <DataTableCell
            key={column.id}
            cell={column}
            data={data}
            storageHelpers={storageHelpers}
          />
        ))}</a>
      {(actions || endWithNavigate) && (
        <div
          key={`navigate_${data.id}`}
          className={classes.cellContainer}
          style={{
            width: 'calc(var(--col-navigate-size) * 1px)',
            overflow: 'initial',
          }}
          onMouseDown={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          onClick={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
          onMouseUp={(e) => {
            e.preventDefault();
            e.stopPropagation();
          }}
        >
          {actions && actions(data)}
          {endWithNavigate && (
            <IconButton onClick={() => navigate(link)}>
              <KeyboardArrowRightOutlined />
            </IconButton>
          )}
        </div>
      )}
    </div>
  );
};

export default DataTableLine;
