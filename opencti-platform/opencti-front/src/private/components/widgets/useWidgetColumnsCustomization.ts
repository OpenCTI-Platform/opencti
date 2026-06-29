import { useEffect } from 'react';
import { DropResult } from '@hello-pangea/dnd';
import type { WidgetColumn } from '../../../utils/widget/widget';

const useWidgetColumnsCustomization = (
  availableColumns: WidgetColumn[],
  value: WidgetColumn[],
  onChange: (columns: WidgetColumn[]) => void,
) => {
  useEffect(() => {
    const filteredColumns = value.filter((col) => availableColumns.some((availableCol) => availableCol.attribute === col.attribute));
    if (filteredColumns.length !== value.length) {
      onChange(filteredColumns);
    }
  }, [availableColumns, value]);

  const handleDragEndSingleColumn = (result: DropResult) => {
    if (!result.destination) return;

    const reordered = Array.from(value);
    const [moved] = reordered.splice(result.source.index, 1);
    reordered.splice(result.destination.index, 0, moved);
    onChange(reordered);
  };

  const handleDragEndDoubleColumns = (result: DropResult) => {
    if (!result.destination) return;

    const col1 = value.filter((_, i) => i % 2 === 0);
    const col2 = value.filter((_, i) => i % 2 === 1);

    const sourceList = result.source.droppableId === 'col_1' ? col1 : col2;
    const destList = result.destination.droppableId === 'col_1' ? col1 : col2;
    const isSameColumn = result.source.droppableId === result.destination.droppableId;

    const [moved] = sourceList.splice(result.source.index, 1);
    if (isSameColumn) {
      sourceList.splice(result.destination.index, 0, moved);
    } else {
      destList.splice(result.destination.index, 0, moved);
    }

    const reordered: WidgetColumn[] = [];
    const maxLen = Math.max(col1.length, col2.length);
    for (let i = 0; i < maxLen; i++) {
      if (col1[i]) reordered.push(col1[i]);
      if (col2[i]) reordered.push(col2[i]);
    }
    onChange(reordered);
  };

  const handleToggleColumn = (attribute?: string | null) => {
    const columnExists = value.some((col) => col.attribute === attribute);
    if (columnExists) {
      onChange(value.filter((col) => col.attribute !== attribute));
    } else {
      const columnToAdd = availableColumns.find((col) => col.attribute === attribute);
      if (columnToAdd) {
        onChange([...value, columnToAdd]);
      }
    }
  };

  const formatColumnName = ({ attribute, label }: WidgetColumn) => (label ? label : attribute ?? '');

  return {
    handleDragEndSingleColumn,
    handleDragEndDoubleColumns,
    handleToggleColumn,
    formatColumnName,
  };
};

export default useWidgetColumnsCustomization;
