import React, { FunctionComponent, useState } from 'react';
import { DragDropContext, Draggable, Droppable, DropResult } from '@hello-pangea/dnd';
import { List, ListItem, ListItemIcon, ListItemText, ListItemSecondaryAction, IconButton, Select, MenuItem, AccordionDetails } from '@mui/material';
import { useTheme } from '@mui/styles';
import { DeleteOutlined, DragIndicatorOutlined } from '@mui/icons-material';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import type { WidgetColumn } from '../../../../utils/widget/widget';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';

type WidgetConfigColumnsCustomizationProps = {
  availableColumns: WidgetColumn[];
  readonly columns?: WidgetColumn[];
  setColumns: (columns: WidgetColumn[]) => void;
};

const WidgetConfigColumnsCustomization: FunctionComponent<WidgetConfigColumnsCustomizationProps> = ({
  availableColumns,
  columns = [],
  setColumns,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();
  const [newColumn, setNewColumn] = useState<string | null>(null);

  const handleDragEnd = (result: DropResult) => {
    if (!result.destination) return;

    const reorderedColumns = Array.from(columns);
    const [movedColumn] = reorderedColumns.splice(result.source.index, 1);
    reorderedColumns.splice(result.destination.index, 0, movedColumn);

    setColumns(reorderedColumns);
  };

  const handleRemove = (attribute: string) => {
    setColumns(columns.filter((col) => col.attribute !== attribute));
  };

  return (
    <Accordion sx={{ width: '100%' }}>
      <AccordionSummary
        aria-controls="custom_columns_content"
        id="custom_columns_header"
      >
        <ListItemText primary={t_i18n('Customize Columns')} />
      </AccordionSummary>
      <AccordionDetails id="custom_columns_content">
        <DragDropContext onDragEnd={handleDragEnd}>
          <Droppable droppableId="custom_columns_list">
            {(providedDrop) => (
              <List
                ref={providedDrop.innerRef}
                {...providedDrop.droppableProps}
                sx={{
                  width: '100%',
                  background: theme.palette.background.paper,
                  padding: '0',
                }}
              >
                <ListItem divider sx={{ background: theme.palette.background.nav }}>
                  <ListItemIcon />

                  <ListItemText
                    sx={{
                      paddingRight: theme.spacing(2),
                    }}
                  >
                    <Select
                      value={newColumn || ''}
                      onChange={(e) => {
                        const selectedColumn = e.target.value;
                        const columnToAdd = availableColumns.find((col) => col.attribute === selectedColumn);
                        if (columnToAdd) {
                          setColumns([...columns, columnToAdd]);
                        }
                        setNewColumn(null); // Reset selection
                      }}
                      displayEmpty
                      fullWidth
                      variant="standard"
                      placeholder={t_i18n('Select a column to add')}
                    >
                      {availableColumns
                        .filter((col) => !columns.some((c) => c.attribute === col.attribute))
                        .map((availableColumn) => availableColumn.attribute && (
                        <MenuItem key={availableColumn.attribute} value={availableColumn.attribute}>
                          {t_i18n(availableColumn.attribute)}
                        </MenuItem>
                        ))}
                    </Select>
                  </ListItemText>
                </ListItem>

                {columns.map((column, index) => (
                  <Draggable key={column.attribute} draggableId={column.attribute ?? ''} index={index}>
                    {(providedDrag, snapshotDrag) => (
                      <ListItem
                        ref={providedDrag.innerRef}
                        {...providedDrag.draggableProps}
                        divider
                        sx={{
                          ...providedDrag.draggableProps.style,
                          background: snapshotDrag.isDragging
                            ? theme.palette.background.accent
                            : theme.palette.background.paper,
                        }}
                      >
                        <ListItemIcon {...providedDrag.dragHandleProps}>
                          <DragIndicatorOutlined />
                        </ListItemIcon>

                        <ListItemText primary={t_i18n(column.attribute)} />

                        <ListItemSecondaryAction>
                          <IconButton onClick={() => column.attribute && handleRemove(column.attribute)}>
                            <DeleteOutlined />
                          </IconButton>
                        </ListItemSecondaryAction>
                      </ListItem>
                    )}
                  </Draggable>
                ))}
                {providedDrop.placeholder}
              </List>
            )}
          </Droppable>
        </DragDropContext>
      </AccordionDetails>
    </Accordion>
  );
};

export default WidgetConfigColumnsCustomization;
