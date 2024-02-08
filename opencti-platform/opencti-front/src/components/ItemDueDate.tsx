import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from './i18n';

const useStyles = makeStyles(() => ({
  chip: {
    borderRadius: 4,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    borderRadius: 4,
  },
}));

const ItemDueDate = ({ due_date, variant }: { due_date: string | null, variant: string }) => {
  const { fld, fldt } = useFormatter();
  const classes = useStyles();
  const isoDate = new Date().toISOString();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  const label = variant === 'inList' ? fld(due_date) : fldt(due_date);
  if (due_date) {
    return (
      <Chip
        classes={{ root: style }}
        variant="outlined"
        label={label}
        color={due_date < isoDate ? 'error' : 'info'}
      />
    );
  }
  return (
    <>-</>
  );
};

export default ItemDueDate;
