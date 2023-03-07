import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { useFormatter } from './i18n';
import { useLevel } from '../utils/hooks/useScale';
import { hexToRGB } from '../utils/Colors';

const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 120,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 80,
  },
}));

interface ItemConfidenceProps {
  confidence: number | null,
  variant?: string,
  entityType?: string,
}

const ItemConfidence: FunctionComponent<ItemConfidenceProps> = ({ confidence, variant, entityType }) => {
  const { t } = useFormatter();
  const classes = useStyles();

  const { level: confidenceLevel } = useLevel(entityType ?? null, 'confidence', confidence);

  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  return (
    <Chip
      classes={{ root: style }}
      style={{
        color: confidenceLevel.color,
        backgroundColor: hexToRGB(confidenceLevel.color),
      }}
      label={t(confidenceLevel.label)}
    />
  );
};

export default ItemConfidence;
