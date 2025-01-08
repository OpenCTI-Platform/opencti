import React, { FunctionComponent } from 'react';
import { DragDropContext, Draggable, Droppable } from '@hello-pangea/dnd';
import List from '@mui/material/List';
import ListItem from '@mui/material/ListItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import ListItemSecondaryAction from '@mui/material/ListItemSecondaryAction';
import Switch from '@mui/material/Switch';
import { useTheme } from '@mui/styles';
import DragIndicatorOutlinedIcon from '@mui/icons-material/DragIndicatorOutlined';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import type { WidgetColumn } from '../../../../utils/widget/widget';

type WidgetConfigColumnsCustomizationProps = {
  availableColumns: WidgetColumn[];
  columns?: WidgetColumn[];
  setColumns: (columns: WidgetColumn[]) => void;
};

const WidgetConfigColumnsCustomization: FunctionComponent<WidgetConfigColumnsCustomizationProps> = ({
  availableColumns,
  columns = [],
  setColumns,
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme<Theme>();

  const handleDragEnd = (result: any) => {
    if (!result.destination) return;

    const reorderedColumns = Array.from(columns);
    const [movedColumn] = reorderedColumns.splice(result.source.index, 1);
    reorderedColumns.splice(result.destination.index, 0, movedColumn);

    setColumns(reorderedColumns);
  };

  const handleToggle = (attribute: string) => {
    const isColumnSelected = columns.some((col) => col.attribute === attribute);
    if (isColumnSelected) {
      setColumns(columns.filter((col) => col.attribute !== attribute));
    } else {
      const columnToAdd = availableColumns.find((col) => col.attribute === attribute);
      if (columnToAdd) {
        setColumns([...columns, columnToAdd]);
      }
    }
  };

  return (
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
            {availableColumns.map((column, index) => (
              <Draggable key={column.attribute} draggableId={column.attribute} index={index}>
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
                    secondaryAction={
                      <ListItemSecondaryAction>
                        <Switch
                          edge="end"
                          checked={columns?.some((col) => col.attribute === column.attribute)}
                          onChange={() => handleToggle(column.attribute)}
                        />
                      </ListItemSecondaryAction>
                    }
                  >
                    <ListItemIcon {...providedDrag.dragHandleProps}>
                      <DragIndicatorOutlinedIcon />
                    </ListItemIcon>
                    <ListItemText primary={t_i18n(column.attribute)} />
                  </ListItem>
                )}
              </Draggable>
            ))}
            {providedDrop.placeholder}
          </List>
        )}
      </Droppable>
    </DragDropContext>
  );
};

export default WidgetConfigColumnsCustomization;
