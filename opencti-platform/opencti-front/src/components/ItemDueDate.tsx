import React from 'react';
import Tag from '@common/tag/Tag';
import { useFormatter } from './i18n';
import { EMPTY_VALUE } from '../utils/String';
import { useTheme } from '@mui/material/styles';

const ItemDueDate = ({ due_date, variant }: { due_date: string | null; variant: string }) => {
  const { ftd, fldt } = useFormatter();
  const theme = useTheme();
  const isoDate = new Date().toISOString();
  // In lists, the due date follows the date display of tables, with its long month by default.
  const label = variant === 'inList' ? ftd(due_date, 'long') : fldt(due_date);
  if (due_date) {
    return (
      <Tag
        label={label}
        color={due_date < isoDate ? theme.palette.error.main : theme.palette.primary.main}
      />
    );
  }
  return <>{EMPTY_VALUE}</>;
};

export default ItemDueDate;
