import React, { CSSProperties } from 'react';
import { Skeleton, Checkbox, IconButton, Box, SxProps } from '@mui/material';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import makeStyles from '@mui/styles/makeStyles';
import { createStyles, useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import type { DataTableCellProps, DataTableLineProps } from '../dataTableTypes';
import { DataTableColumn, DataTableVariant } from '../dataTableTypes';
import type { Theme } from '../../Theme';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import { useDataTableContext } from './DataTableContext';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme, { cell?: DataTableColumn, clickable?: boolean }>((theme) => createStyles({
  cellContainer: ({ cell }) => ({
    display: 'flex',
    width: `${cell?.percentWidth}%`,
    height: theme.spacing(6),
    alignItems: 'center',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    whiteSpace: 'nowrap',
    flex: '0 0 auto',
  }),
}));

const DataTableLineDummy = () => {
  const { columns } = useDataTableContext();
  const columnStyle = (c: typeof columns[0]) => ({
    paddingLeft: '4px',
    paddingRight: '8px',
    flex: '0 0 auto',
    width: c.percentWidth ? `${c.percentWidth}%` : `${SELECT_COLUMN_SIZE}px`,
  });

  return (
    <div style={{ display: 'flex' }}>
      {columns.map((column) => (
        <div key={column.id} style={columnStyle(column)}>
          <Skeleton variant="text" height={35} />
        </div>
      ))}
    </div>
  );
};

export const DataTableLinesDummy = ({ number = 10 }: { number?: number }) => {
  const { columns, actions } = useDataTableContext();
  const startsWithSelect = columns.at(0)?.id === 'select';
  const endsWithNavigate = columns.at(-1)?.id === 'navigate';

  let offset = 0;
  if (startsWithSelect) offset += SELECT_COLUMN_SIZE;
  if (endsWithNavigate || actions) offset += SELECT_COLUMN_SIZE;

  return (
    <div style={{ paddingRight: offset }}>
      {Array(Math.min(number, 25)).fill(0).map((_, idx) => (<DataTableLineDummy key={idx} />))}
    </div>
  );
};

const DataTableCell = ({
  cell,
  data,
}: DataTableCellProps) => {
  const classes = useStyles({ cell });
  const { useDataCellHelpers } = useDataTableContext();
  const helpers = useDataCellHelpers(cell);

  const cellStyle: CSSProperties = {
    display: 'flex',
    paddingLeft: '8px',
    paddingRight: '8px',
    width: '100%',
    alignItems: 'center',
    gap: '3px',
    fontSize: '13px',
  };

  return (
    <div key={`${cell.id}_${data.id}`} className={classes.cellContainer}>
      <div style={cellStyle}>
        {cell.render?.(data, helpers) ?? (<div>-</div>)}
      </div>
    </div>
  );
};

const DataTableLine = ({
  row,
  index,
  onToggleShiftEntity,
}: DataTableLineProps) => {
  const navigate = useNavigate();
  const theme = useTheme<Theme>();
  const classes = useStyles({ });

  const {
    columns,
    useLineData,
    useDataTableToggle,
    useComputeLink,
    actions,
    disableNavigation,
    onLineClick,
    selectOnLineClick,
    variant,
    useDataTablePaginationLocalStorage: {
      viewStorage: { redirectionMode },
    },
  } = useDataTableContext();
  const data = useLineData(row);

  let link = useComputeLink(data);
  if (redirectionMode && redirectionMode !== 'overview') {
    link = `${link}/${redirectionMode}`;
  }

  const navigable = !disableNavigation && !onLineClick && !selectOnLineClick;
  const clickable = !!(navigable || selectOnLineClick || onLineClick);

  const {
    selectAll,
    deSelectedElements,
    selectedElements,
    onToggleEntity,
  } = useDataTableToggle;

  const startsWithSelect = columns.at(0)?.id === 'select';
  const endsWithNavigate = columns.at(-1)?.id === 'navigate';

  const handleSelectLine = (event: React.MouseEvent) => {
    if (event.shiftKey) {
      onToggleShiftEntity(index, data, event);
    } else {
      onToggleEntity(data, event);
    }
  };

  const handleNavigate = (event: React.MouseEvent) => {
    if (!navigable) return;
    if (event.ctrlKey) {
      window.open(link, '_blank');
    } else {
      navigate(link);
    }
  };

  const handleRowClick = (event: React.MouseEvent) => {
    if (!clickable) return;
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

  let offset = 0;
  if (startsWithSelect) offset += SELECT_COLUMN_SIZE;
  if (endsWithNavigate || actions) offset += SELECT_COLUMN_SIZE;

  const linkStyle: CSSProperties = {
    display: 'flex',
    color: 'inherit',
  };

  const containerStyle: SxProps = {
    cursor: clickable ? 'pointer' : 'unset',
    paddingRight: `${offset}px`,
    '& a > div': {
      borderBottom: `1px solid ${theme.palette.divider}`,
    },
    '& a:hover > div': clickable ? {
      backgroundColor:
        theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .1)'
          : 'rgba(0, 0, 0, .1)',
    } : {},
  };

  return (
    <Box
      key={row.id}
      sx={containerStyle}
      // We need both to handle accessibility and widget.
      onMouseDown={variant === DataTableVariant.widget ? handleNavigate : undefined}
      onClick={variant !== DataTableVariant.widget ? handleRowClick : undefined}
      data-testid={getMainRepresentative(data)}
    >
      <a
        style={linkStyle}
        href={navigable ? link : undefined}
      >
        {startsWithSelect && (
          <div
            key={`select_${data.id}`}
            className={classes.cellContainer}
            style={{ width: SELECT_COLUMN_SIZE }}
          >
            <Checkbox
              onClick={handleSelectLine}
              sx={{
                marginRight: 1,
                flex: '0 0 auto',
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

        {columns.slice(startsWithSelect ? 1 : 0, (actions || disableNavigation) ? undefined : -1).map((column) => (
          <DataTableCell
            key={column.id}
            cell={column}
            data={data}
          />
        ))}

        {(actions || endsWithNavigate) && (
          <div
            key={`navigate_${data.id}`}
            className={classes.cellContainer}
            style={{
              width: SELECT_COLUMN_SIZE,
              overflow: 'initial',
            }}
          >
            {actions && actions(data)}
            {endsWithNavigate && (
              <IconButton onClick={() => navigate(link)}>
                <KeyboardArrowRightOutlined />
              </IconButton>
            )}
          </div>
        )}
      </a>
    </Box>
  );
};

export default DataTableLine;
