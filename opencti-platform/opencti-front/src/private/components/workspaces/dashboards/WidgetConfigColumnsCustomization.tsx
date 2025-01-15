import React, { FunctionComponent } from 'react';
import { DragDropContext, Draggable, Droppable, DropResult } from '@hello-pangea/dnd';
import { List, ListItem, ListItemIcon, ListItemText, ListItemSecondaryAction, IconButton, Checkbox, Typography, Box, AccordionDetails } from '@mui/material';
import { Close, DragIndicatorOutlined } from '@mui/icons-material';
import { useTheme } from '@mui/styles';
import Button from '@mui/material/Button';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import type { WidgetColumn } from '../../../../utils/widget/widget';
import { Accordion, AccordionSummary } from '../../../../components/Accordion';

type WidgetConfigColumnsCustomizationProps = {
  availableColumns: WidgetColumn[];
  defaultColumns: WidgetColumn[];
  columns?: WidgetColumn[];
  setColumns: (columns: WidgetColumn[]) => void;
};

const WidgetConfigColumnsCustomization: FunctionComponent<WidgetConfigColumnsCustomizationProps> = ({
  availableColumns,
  defaultColumns,
  columns = [],
  setColumns,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const handleDragEnd = (result: DropResult) => {
    if (!result.destination) return;

    const reorderedColumns = Array.from(columns);
    const [movedColumn] = reorderedColumns.splice(result.source.index, 1);
    reorderedColumns.splice(result.destination.index, 0, movedColumn);

    setColumns(reorderedColumns);
  };

  const handleToggleColumn = (attribute?: string | null) => {
    const columnExists = columns.some((col) => col.attribute === attribute);
    if (columnExists) {
      setColumns(columns.filter((col) => col.attribute !== attribute));
    } else {
      const columnToAdd = availableColumns.find((col) => col.attribute === attribute);
      if (columnToAdd) {
        setColumns([...columns, columnToAdd]);
      }
    }
  };

  const formatColumnName = ({ attribute, label }: WidgetColumn) => (label ? t_i18n(label) : t_i18n(attribute ?? ''));

  return (
    <Accordion sx={{ width: '100%' }}>
      <AccordionSummary>
        <Typography> {t_i18n('Customize columns')} </Typography>
      </AccordionSummary>

      <AccordionDetails sx={{ background: 'none', paddingBlock: theme.spacing(2) }} >
        <Box sx={{ display: 'flex', width: '100%', gap: theme.spacing(2) }}>
          {/* Available Columns */}
          <Box sx={{ flex: 1 }}>
            <Typography variant="h4">{`${t_i18n('Available Columns')} (${availableColumns.length})`}</Typography>
            <List sx={{ border: `1px solid ${theme.palette.common.white}`, borderRadius: `${theme.borderRadius}px` }}>
              {availableColumns.map((column) => (
                <ListItem
                  disablePadding
                  key={column.attribute}
                  sx={{ height: 42 }}
                >
                  <Checkbox
                    checked={columns.some((col) => col.attribute === column.attribute)}
                    onChange={() => handleToggleColumn(column.attribute)}
                  />
                  <ListItemText primary={formatColumnName(column)} />
                </ListItem>
              ))}
            </List>
          </Box>

          {/* Selected Columns */}
          <Box sx={{ flex: 1, height: '100%' }}>
            <Typography variant="h4">{`${t_i18n('Selected Columns')} (${columns.length})`}</Typography>
            <DragDropContext onDragEnd={handleDragEnd}>
              <Droppable droppableId="selected_columns">
                {(providedDrop) => (
                  <List
                    ref={providedDrop.innerRef}
                    {...providedDrop.droppableProps}
                    sx={{
                      border: `1px solid ${theme.palette.common.white}`,
                      borderRadius: `${theme.borderRadius}px`,
                      paddingBlock: theme.spacing(1),
                    }}
                  >
                    {columns.map((column, index) => (
                      <Draggable key={column.attribute} draggableId={column.attribute ?? ''} index={index}>
                        {(providedDrag, snapshotDrag) => (
                          <ListItem
                            ref={providedDrag.innerRef}
                            {...providedDrag.draggableProps}
                            divider={index < columns.length - 1}
                            sx={{
                              ...providedDrag.draggableProps.style,
                              background: snapshotDrag.isDragging ? 'rgba(0, 0, 0, 0.05)' : 'inherit',
                              height: 42,
                            }}
                          >
                            <ListItemIcon {...providedDrag.dragHandleProps}>
                              <DragIndicatorOutlined />
                            </ListItemIcon>

                            <ListItemText primary={formatColumnName(column)} />

                            <ListItemSecondaryAction>
                              <IconButton onClick={() => handleToggleColumn(column.attribute)}>
                                <Close />
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
          </Box>
        </Box>

        <Box sx={{ display: 'flex', marginTop: 2, justifyContent: 'flex-end' }} >
          <Button
            variant='outlined'
            style={{ marginTop: '2.5px', marginLeft: '4px' }}
            onClick={() => setColumns(defaultColumns)}
          >
            {t_i18n('Reset')}
          </Button>
        </Box>
      </AccordionDetails>
    </Accordion>
  );
};

export default WidgetConfigColumnsCustomization;
