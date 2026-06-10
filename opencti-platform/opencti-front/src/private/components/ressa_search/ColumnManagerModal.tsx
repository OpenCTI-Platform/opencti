import React, { useEffect, useMemo, useState } from 'react';
import {
  Box,
  Button,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Switch,
} from '@mui/material';
import { DragIndicator } from '@mui/icons-material';
import { DragDropContext, Draggable, Droppable, type DropResult } from '@hello-pangea/dnd';
import { useFormatter } from '../../../components/i18n';
import type { ColumnDefinition } from './ressaSearchColumns';

interface ColumnManagerModalProps {
  open: boolean;
  onClose: () => void;
  columns: ColumnDefinition[];
  onChange: (columns: ColumnDefinition[]) => void;
}

const ColumnManagerModal: React.FC<ColumnManagerModalProps> = ({
  open,
  onClose,
  columns,
  onChange,
}) => {
  const { t_i18n } = useFormatter();
  const [draftColumns, setDraftColumns] = useState<ColumnDefinition[]>(columns);

  useEffect(() => {
    if (open) {
      setDraftColumns([...columns].sort((a, b) => a.order - b.order));
    }
  }, [open, columns]);

  const sortedDraftColumns = useMemo(
    () => [...draftColumns].sort((a, b) => a.order - b.order),
    [draftColumns],
  );

  const handleDragEnd = (result: DropResult) => {
    if (!result.destination) {
      return;
    }

    const reorderedColumns = Array.from(sortedDraftColumns);
    const [movedColumn] = reorderedColumns.splice(result.source.index, 1);
    reorderedColumns.splice(result.destination.index, 0, movedColumn);

    setDraftColumns(reorderedColumns.map((column, index) => ({
      ...column,
      order: index,
    })));
  };

  const handleToggleVisibility = (columnId: string) => {
    setDraftColumns((current) => current.map((column) => (
      column.id === columnId && !column.required
        ? { ...column, visible: !column.visible }
        : column
    )));
  };

  const handleCancel = () => {
    onClose();
  };

  const handleApply = () => {
    onChange(sortedDraftColumns);
    onClose();
  };

  return (
    <Dialog open={open} onClose={handleCancel} maxWidth="xs" fullWidth>
      <DialogTitle>{t_i18n('Manage Columns')}</DialogTitle>
      <DialogContent>
        <DragDropContext onDragEnd={handleDragEnd}>
          <Droppable droppableId="ressa_search_columns">
            {(providedDrop) => (
              <List
                ref={providedDrop.innerRef}
                {...providedDrop.droppableProps}
                sx={{ py: 0 }}
              >
                {sortedDraftColumns.map((column, index) => (
                  <Draggable key={column.id} draggableId={column.id} index={index}>
                    {(providedDrag, snapshotDrag) => (
                      <ListItem
                        ref={providedDrag.innerRef}
                        {...providedDrag.draggableProps}
                        sx={{
                          ...providedDrag.draggableProps.style,
                          backgroundColor: snapshotDrag.isDragging ? 'action.hover' : 'transparent',
                          borderRadius: 1,
                          px: 1,
                        }}
                        secondaryAction={(
                          <Switch
                            edge="end"
                            checked={column.visible}
                            disabled={column.required}
                            onChange={() => handleToggleVisibility(column.id)}
                          />
                        )}
                      >
                        <ListItemIcon
                          {...providedDrag.dragHandleProps}
                          sx={{ minWidth: 36, cursor: 'grab' }}
                        >
                          <DragIndicator fontSize="small" color="action" />
                        </ListItemIcon>
                        <ListItemText primary={t_i18n(column.label)} />
                      </ListItem>
                    )}
                  </Draggable>
                ))}
                {providedDrop.placeholder}
              </List>
            )}
          </Droppable>
        </DragDropContext>
      </DialogContent>
      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Box sx={{ display: 'flex', gap: 1 }}>
          <Button variant="outlined" onClick={handleCancel}>
            {t_i18n('Cancel')}
          </Button>
          <Button variant="contained" color="primary" onClick={handleApply}>
            {t_i18n('Apply')}
          </Button>
        </Box>
      </DialogActions>
    </Dialog>
  );
};

export default ColumnManagerModal;
