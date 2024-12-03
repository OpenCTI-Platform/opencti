import React, { CSSProperties, FunctionComponent, useMemo, useRef, useState } from 'react';
import Checkbox from '@mui/material/Checkbox';
import { DragIndicatorOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import { DragDropContext, Draggable, DraggableLocation, Droppable } from '@hello-pangea/dnd';
import MenuItem from '@mui/material/MenuItem';
import { PopoverProps } from '@mui/material/Popover/Popover';
import { useTheme } from '@mui/styles';
import Box from '@mui/material/Box';
import { SxProps } from '@mui/material';
import { DataTableColumn, DataTableColumns, DataTableHeadersProps, DataTableVariant } from '../dataTableTypes';
import DataTableHeader, { SELECT_COLUMN_SIZE } from './DataTableHeader';
import type { Theme } from '../../Theme';
import { useDataTableContext } from './DataTableContext';

const DataTableHeaders: FunctionComponent<DataTableHeadersProps> = ({
  dataTableToolBarComponent,
}) => {
  const theme = useTheme<Theme>();
  const {
    columns,
    setColumns,
    useDataTableToggle: {
      selectAll,
      numberOfSelectedElements,
      handleToggleSelectAll,
    },
    formatter: { t_i18n },
    availableFilterKeys,
    onAddFilter,
    onSort,
    disableToolBar,
    disableSelectAll,
    actions,
    variant,
    useDataTablePaginationLocalStorage: {
      viewStorage: { sortBy, orderAsc },
    },
  } = useDataTableContext();
  const containerRef = useRef<HTMLDivElement | null>(null);

  const [activeColumn, setActiveColumn] = useState<DataTableColumn | undefined>();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const handleClose = () => {
    setAnchorEl(null);
    setActiveColumn(undefined);
  };

  const handleToggleVisibility = (columnId: string) => {
    const newColumns = [...columns];
    const currentColumn = newColumns.find(({ id }) => id === columnId);
    if (!currentColumn) {
      return;
    }
    currentColumn.visible = currentColumn.visible ?? true;
    setColumns(newColumns);
  };

  const draggableColumns = useMemo(() => columns.filter(({ id }) => !['select', 'navigate'].includes(id)), [columns]);

  const hasSelectCheckboxes = columns.some(({ id }) => id === 'select');
  const hasSelectedElements = numberOfSelectedElements > 0 || selectAll;
  const endsWithNavigate = columns.at(-1)?.id === 'navigate';

  let offset = 0;
  if (hasSelectCheckboxes) offset += SELECT_COLUMN_SIZE;
  if (endsWithNavigate || actions) offset += SELECT_COLUMN_SIZE;

  const bgColor = variant === DataTableVariant.widget
    ? theme.palette.background.paper
    : theme.palette.background.default;

  const checkboxStyle: CSSProperties = {
    background: hasSelectedElements
      ? theme.palette.background.accent
      : bgColor,
    width: SELECT_COLUMN_SIZE,
  };

  const showToolbar = numberOfSelectedElements > 0 && !disableToolBar;
  const containerStyle: SxProps = {
    paddingRight: showToolbar ? 0 : `${offset}px`,
    position: 'sticky',
    top: 0,
    width: '100%',
    zIndex: 10,
    '& > div > div': {
      background: bgColor,
    },
  };

  return (
    <Box ref={containerRef} sx={containerStyle}>
      <div style={{ display: 'flex', height: 42 }}>
        {hasSelectCheckboxes && (
          <div data-testid="dataTableCheckAll" style={checkboxStyle}>
            <Checkbox
              checked={selectAll}
              sx={{
                marginRight: 1,
                flex: '0 0 auto',
                '&:hover': {
                  background: 'transparent',
                },
              }}
              onChange={handleToggleSelectAll}
              disabled={!handleToggleSelectAll || disableSelectAll}
            />
          </div>
        )}
        {showToolbar ? dataTableToolBarComponent : (
          <>
            {anchorEl && (
              <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
                {columns.some(({ id }) => id === 'todo-navigate') && (
                  <DragDropContext
                    key={(new Date()).toString()}
                    onDragEnd={({ source, destination }) => {
                      const result = Array.from(draggableColumns);
                      const [removed] = result.splice(source.index, 1);
                      result.splice((destination as DraggableLocation).index, 0, removed);

                      const newColumns: DataTableColumns = [
                        columns.at(0),
                        ...(result.map((c, index) => {
                          const currentColumn = columns.find(({ id }) => id === c.id);
                          return ({ ...currentColumn, order: index });
                        })),
                        columns.at(-1),
                      ] as DataTableColumns;

                      setColumns(newColumns);
                    }}
                  >
                    <Droppable droppableId="droppable-list">
                      {(provided) => (
                        <div ref={provided.innerRef} {...provided.droppableProps}>
                          {draggableColumns.map((c, index) => (
                            <Draggable
                              key={index}
                              draggableId={c.id}
                              index={index}
                            >
                              {(item) => (
                                <MenuItem
                                  ref={item.innerRef}
                                  {...item.draggableProps}
                                  {...item.dragHandleProps}
                                >
                                  <DragIndicatorOutlined fontSize="small" />
                                  <Checkbox
                                    onClick={() => handleToggleVisibility(c.id)}
                                    checked={c.visible}
                                  />
                                  {c.label}
                                </MenuItem>
                              )}
                            </Draggable>
                          ))}
                          {provided.placeholder}
                        </div>
                      )}
                    </Droppable>
                  </DragDropContext>
                )}
                {activeColumn?.isSortable && (<MenuItem onClick={() => onSort(activeColumn.id, true)}>{t_i18n('Sort Asc')}</MenuItem>)}
                {activeColumn?.isSortable && (<MenuItem onClick={() => onSort(activeColumn.id, false)}>{t_i18n('Sort Desc')}</MenuItem>)}
                {(activeColumn && availableFilterKeys?.includes(activeColumn.id)) && (
                  <MenuItem
                    onClick={() => {
                      onAddFilter(activeColumn.id);
                      handleClose();
                    }}
                  >
                    {t_i18n('Add filtering')}
                  </MenuItem>
                )}
              </Menu>
            )}
            {columns
              .filter(({ id }) => !['select', 'navigate'].includes(id))
              .map((column) => (
                <DataTableHeader
                  key={column.id}
                  column={column}
                  setAnchorEl={setAnchorEl}
                  isActive={activeColumn?.id === column.id}
                  setActiveColumn={setActiveColumn}
                  containerRef={containerRef}
                  sortBy={sortBy === column.id}
                  orderAsc={!!orderAsc}
                />
              ))}
            {(actions || endsWithNavigate) && (
              <div style={{ width: '42px', flex: '0 0 auto' }} />
            )}
          </>
        )}
      </div>
    </Box>
  );
};

export default DataTableHeaders;
