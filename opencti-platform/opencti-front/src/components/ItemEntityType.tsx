import Chip from '@mui/material/Chip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { hexToRGB, itemColor } from '../utils/Colors';
import { useFormatter } from './i18n';

const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 13,
    lineHeight: '12px',
    height: 20,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 120,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    width: 120,
    textTransform: 'uppercase',
    borderRadius: 4,
  },
}));

interface ItemEntityTypeProps {
  entityType: string;
  variant?: string;
}

const ItemEntityType: FunctionComponent<ItemEntityTypeProps> = ({
  variant = 'inList',
  entityType,
}) => {
  const classes = useStyles();
  const { t_i18n } = useFormatter();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  return (
    <Chip
      classes={{ root: style }}
      style={{
        backgroundColor: hexToRGB(itemColor(entityType), 0.08),
        color: itemColor(entityType),
        border: `1px solid ${itemColor(entityType)}`,
      }}
      label={t_i18n(`entity_${entityType}`)}
    />
  );
};

export default ItemEntityType;
