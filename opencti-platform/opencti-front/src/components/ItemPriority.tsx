import React, { FunctionComponent } from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

interface ItemPriorityProps {
  label: string;
  priority?: string | null;
  variant?: 'inList';
}

const ItemPriority: FunctionComponent<ItemPriorityProps> = ({
  label,
  priority,
}) => {
  const theme = useTheme<Theme>();

  let priorityColor = theme.palette.severity.info;
  switch (priority) {
    case 'P4':
      priorityColor = theme.palette.severity.low;
      break;
    case 'P3':
      priorityColor = theme.palette.severity.medium;
      break;
    case 'P2':
      priorityColor = theme.palette.severity.high;
      break;
    case 'P1':
      priorityColor = theme.palette.severity.critical;
      break;
    default:
      priorityColor = theme.palette.severity.default;
      break;
  }

  return <Tag label={label} color={priorityColor} />;
};

export default ItemPriority;
