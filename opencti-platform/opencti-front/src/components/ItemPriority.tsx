import React, { FunctionComponent } from 'react';
import Tag from '@common/tag/Tag';
import { EMPTY_VALUE } from '../utils/String';
import { priorityTone } from '../utils/severityTone';

interface ItemPriorityProps {
  label: string;
  priority?: string | null;
  variant?: 'inList';
}

const ItemPriority: FunctionComponent<ItemPriorityProps> = ({
  label,
  priority,
}) => {
  if (!priority) {
    return <>{EMPTY_VALUE}</>;
  }

  return <Tag label={label} severity={priorityTone(priority)} />;
};

export default ItemPriority;
