import React, { FunctionComponent, useMemo, useState } from 'react';
import Checkbox from '@mui/material/Checkbox';
import { DragIndicatorOutlined } from '@mui/icons-material';
import Menu from '@mui/material/Menu';
import { DragDropContext, Draggable, DraggableLocation, Droppable } from '@hello-pangea/dnd';
import MenuItem from '@mui/material/MenuItem';
import { PopoverProps } from '@mui/material/Popover/Popover';
import { useTheme } from '@mui/styles';
import { DataTableColumn, DataTableColumns, DataTableHeadersProps, LocalStorageColumns } from '../dataTableTypes';
import DataTableHeader from './DataTableHeader';
import type { Theme } from '../../Theme';
import { useDataTableContext } from './DataTableContext';

const DataTableHeaders: FunctionComponent<DataTableHeadersProps> = ({
  containerRef,
  effectiveColumns,
  dataTableToolBarComponent,
  sortBy,
  orderAsc,
}) => {
  const theme = useTheme<Theme>();
  const {
    columns,
    setColumns,
    useDataTableToggle,
    useDataTableColumnsLocalStorage,
    formatter,
    availableFilterKeys,
    onAddFilter,
    onSort,
    disableToolBar,
    disableSelectAll,
  } = useDataTableContext();
  const { t_i18n } = formatter;

  const {
    selectAll,
    numberOfSelectedElements,
    handleToggleSelectAll,
    selectedElements,
  } = useDataTableToggle;

  const [_, setLocalStorageColumns] = useDataTableColumnsLocalStorage;

  const [activeColumn, setActiveColumn] = useState<DataTableColumn | undefined>();
  const [anchorEl, setAnchorEl] = useState<PopoverProps['anchorEl']>(null);
  const handleClose = () => {
    setAnchorEl(null);
    setActiveColumn(undefined);
  };

  const handleToggleVisibility = (columnId: string) => {
    const newColumns = [...effectiveColumns];
    const currentColumn = newColumns.find(({ id }) => id === columnId);
    if (!currentColumn) {
      return;
    }
    currentColumn.visible = currentColumn.visible ?? true;
    setLocalStorageColumns((curr: LocalStorageColumns) => ({ ...curr, [columnId]: { ...curr[columnId], visible: currentColumn.visible } }));
    setColumns(newColumns);
  };

  const ordonableColumns = useMemo(() => effectiveColumns.filter(({ id }) => !['select', 'navigate'].includes(id)), [columns]);
  return (
    <div
      style={{
        display: 'flex',
        width: 'calc(var(--header-table-size) * 1px)',
        height: theme.spacing(6),
        alignItems: 'stretch',
        borderBottom: `1px solid ${theme.palette.divider}`,
        background: (Object.keys(selectedElements ?? {}).length > 0 || selectAll) && !disableSelectAll ? theme.palette.background.accent : 'unset',
      }}
    >
      {effectiveColumns.some(({ id }) => id === 'select') && (
        <div
          data-testid="dataTableCheckAll"
          style={{
            display: 'flex',
            alignSelf: 'center',
            width: 'calc(var(--header-select-size) * 1px)',
          }}
        >
          <Checkbox
            checked={selectAll}
            onChange={handleToggleSelectAll}
            disabled={!handleToggleSelectAll || disableSelectAll}
          />
        </div>
      )}
      {numberOfSelectedElements > 0 && !disableToolBar ? dataTableToolBarComponent : (
        <>
          {anchorEl && (
            <Menu anchorEl={anchorEl} open={Boolean(anchorEl)} onClose={handleClose}>
              {effectiveColumns.some(({ id }) => id === 'todo-navigate') && (
                <DragDropContext
                  key={(new Date()).toString()}
                  onDragEnd={({ draggableId, source, destination }) => {
                    const result = Array.from(ordonableColumns);
                    const [removed] = result.splice(source.index, 1);
                    result.splice((destination as DraggableLocation).index, 0, removed);

                    const newColumns: DataTableColumns = [
                      effectiveColumns.at(0),
                      ...(result.map((c, index) => {
                        const currentColumn = effectiveColumns.find(({ id }) => id === c.id);
                        return ({ ...currentColumn, order: index });
                      })),
                      effectiveColumns.at(-1),
                    ] as DataTableColumns;

                    setColumns(newColumns);
                    setLocalStorageColumns((curr: LocalStorageColumns) => ({ ...curr, [draggableId]: { ...curr[draggableId], order: destination?.index } }));
                  }}
                >
                  <Droppable droppableId="droppable-list">
                    {(provided) => (
                      <div ref={provided.innerRef} {...provided.droppableProps}>
                        {ordonableColumns.map((c, index) => (
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
              {/* <MenuItem onClick={() => handleToggleVisibility(column.id)}>{t_i18n('Hide column')}</MenuItem> */}
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
          {effectiveColumns
            .filter(({ id }) => !['select', 'navigate'].includes(id))
            .map((column) => (
              <DataTableHeader
                key={column.id}
                column={column}
                setAnchorEl={setAnchorEl}
                isActive={activeColumn?.id === column.id}
                setActiveColumn={setActiveColumn}
                setLocalStorageColumns={setLocalStorageColumns}
                containerRef={containerRef}
                sortBy={sortBy === column.id}
                orderAsc={!!orderAsc}
              />
            ))}
          <span style={{ width: 'calc( 42px + 12px )' }} />
        </>
      )}
    </div>
  );
};

export default DataTableHeaders;
