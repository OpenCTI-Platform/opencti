import React, { CSSProperties, useMemo } from 'react';
import { Skeleton, Checkbox, IconButton, Box } from '@mui/material';
import { KeyboardArrowRightOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router-dom';
import type { DataTableCellProps, DataTableLineProps } from '../dataTableTypes';
import { DataTableVariant } from '../dataTableTypes';
import type { Theme } from '../../Theme';
import { getMainRepresentative } from '../../../utils/defaultRepresentatives';
import { SELECT_COLUMN_SIZE } from './DataTableHeader';
import { useDataTableContext } from './DataTableContext';

const cellContainerStyle = (theme: Theme) => ({
  display: 'flex',
  height: theme.spacing(6),
  alignItems: 'center',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  flex: '0 0 auto',
});

const DataTableLineDummy = () => {
  const theme = useTheme<Theme>();
  const { columns, tableWidthState: [tableWidth] } = useDataTableContext();
  return (
    <div style={{ display: 'flex' }}>
      {columns.map((column) => (
        <div
          key={column.id}
          style={{
            paddingLeft: theme.spacing(0.5),
            paddingRight: theme.spacing(1),
            flex: '0 0 auto',
            width: column.percentWidth
              ? Math.round(tableWidth * (column.percentWidth / 100))
              : SELECT_COLUMN_SIZE,
          }}
        >
          <Skeleton variant="text" height={35} />
        </div>
      ))}
    </div>
  );
};

export const DataTableLinesDummy = ({ number = 10 }: { number?: number }) => <>
  {Array(Math.min(number, 25)).fill(0).map((_, idx) => (
    <DataTableLineDummy key={idx} />
  ))}
</>;

const DataTableCell = ({
  cell,
  data,
}: DataTableCellProps) => {
  const theme = useTheme<Theme>();
  const { useDataCellHelpers, tableWidthState: [tableWidth] } = useDataTableContext();
  const helpers = useDataCellHelpers(cell);

  const cellStyle: CSSProperties = {
    display: 'flex',
    paddingLeft: theme.spacing(1),
    paddingRight: theme.spacing(1),
    width: '100%',
    alignItems: 'center',
    gap: theme.spacing(0.5),
    fontSize: '13px',
  };

  return (
    <div
      key={`${cell.id}_${data.id}`}
      style={{
        ...cellContainerStyle(theme),
        width: Math.round(tableWidth * (cell.percentWidth / 100)),
      }}
    >
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

  const {
    columns,
    useLineData,
    useComputeLink,
    actions,
    disableNavigation,
    onLineClick,
    selectOnLineClick,
    variant,
    startsWithAction,
    endsWithAction,
    endsWithNavigate,
    useDataTableToggle: {
      selectAll,
      deSelectedElements,
      selectedElements,
      onToggleEntity,
    },
    useDataTablePaginationLocalStorage: {
      viewStorage: { redirectionMode },
    },
  } = useDataTableContext();

  const data = useLineData(row);

  // Memoize link to avoid recomputations
  let link = useMemo(() => useComputeLink(data), [data]);
  if (redirectionMode && redirectionMode !== 'overview') {
    link = `${link}/${redirectionMode}`;
  }

  const navigable = !disableNavigation && !onLineClick && !selectOnLineClick;
  const clickable = !!(navigable || selectOnLineClick || onLineClick);

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

  const linkStyle: CSSProperties = {
    display: 'flex',
    color: 'inherit',
    borderBottom: `1px solid ${theme.palette.divider}`,
    cursor: clickable ? 'pointer' : 'unset',
  };

  return (
    <Box sx={{
      '&:hover > a': {
        backgroundColor: theme.palette.mode === 'dark'
          ? 'rgba(255, 255, 255, .1)'
          : 'rgba(0, 0, 0, .1)',
      },
    }}
    >
      <a
        style={linkStyle}
        href={navigable ? link : undefined}
        // We need both to handle accessibility and widget.
        onMouseDown={variant === DataTableVariant.widget ? handleNavigate : undefined}
        onClick={variant !== DataTableVariant.widget ? handleRowClick : undefined}
        data-testid={getMainRepresentative(data)}
      >
        {startsWithAction && (
          <div
            key={`select_${data.id}`}
            style={{
              ...cellContainerStyle(theme),
              width: SELECT_COLUMN_SIZE,
            }}
          >
            <Checkbox
              onClick={handleSelectLine}
              sx={{
                marginRight: 1,
                flex: '0 0 auto',
                paddingLeft: 0,
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

        {columns.slice(startsWithAction ? 1 : 0, (actions || disableNavigation) ? undefined : -1).map((column) => (
          <DataTableCell
            key={column.id}
            cell={column}
            data={data}
          />
        ))}

        {endsWithAction && (
          <div
            key={`navigate_${data.id}`}
            style={{
              ...cellContainerStyle(theme),
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
