import React, { FunctionComponent, useState } from 'react';
import { DragDropContext, Draggable, Droppable, DropResult } from '@hello-pangea/dnd';
import { List, ListItem, ListItemIcon, ListItemText, ListItemSecondaryAction, IconButton, Select, MenuItem, AccordionDetails } from '@mui/material';
import { useTheme } from '@mui/styles';
import { DeleteOutlined, DragIndicatorOutlined } from '@mui/icons-material';
import Typography from '@mui/material/Typography';
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

  const formatAttribute = (attribute: string) => attribute.replace('.', '_');

  const handleSelect = (selectedColumnAttribute: string) => {
    const columnToAdd = availableColumns.find((col) => col.attribute === selectedColumnAttribute);
    if (columnToAdd) {
      setColumns([...columns, columnToAdd]);
    }
    setNewColumn(null);
  };

  const handleRemove = (attribute: string) => {
    setColumns(columns.filter((col) => col.attribute !== attribute));
  };

  return (
    <Accordion sx={{ width: '100%' }}>
      <AccordionSummary>
        <Typography> {t_i18n('Customize columns')} </Typography>
      </AccordionSummary>
      <AccordionDetails sx={{ padding: 0 }}>
        <DragDropContext onDragEnd={handleDragEnd}>
          <Droppable droppableId="custom_columns_list">
            {(providedDrop) => (
              <List
                ref={providedDrop.innerRef}
                {...providedDrop.droppableProps}
                sx={{
                  padding: '0',
                }}
              >
                <ListItem divider sx={{ background: theme.palette.background.accent }}>
                  <ListItemIcon />

                  <ListItemText
                    sx={{
                      paddingRight: theme.spacing(2),
                    }}
                  >
                    <Select
                      value={newColumn || ''}
                      onChange={(e) => e.target.value && handleSelect(e.target.value)}
                      fullWidth
                      variant="standard"
                      displayEmpty
                      disabled={
                        availableColumns.filter((col) => !columns.some((c) => c.attribute === col.attribute)).length === 0
                      }
                    >
                      <MenuItem value="" disabled>
                        {t_i18n('Select a column to add')}
                      </MenuItem>
                      {availableColumns
                        .filter((col) => !columns.some((c) => c.attribute === col.attribute))
                        .map((availableColumn) => availableColumn.attribute && (
                        <MenuItem key={availableColumn.attribute} value={availableColumn.attribute}>
                          {formatAttribute(availableColumn.attribute)}
                        </MenuItem>
                        ))}
                    </Select>
                  </ListItemText>
                  <ListItemSecondaryAction />
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

                        <ListItemText primary={column.attribute && formatAttribute(column.attribute)} />

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
