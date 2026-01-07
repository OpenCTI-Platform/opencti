import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { useLevel } from '../utils/hooks/useScale';
import { hexToRGB } from '../utils/Colors';
import { chipInListBasicStyle } from '../utils/chipStyle';
import Tag from '@common/tag/Tag';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    marginRight: 7,
    borderRadius: 4,
    width: 120,
  },
  chipInList: {
    ...chipInListBasicStyle,
    width: 80,
  },
}));

interface ItemConfidenceProps {
  confidence: number | null | undefined;
  variant?: string;
  entityType: string;
}

const ItemConfidence: FunctionComponent<ItemConfidenceProps> = ({ confidence, variant, entityType }) => {
  const classes = useStyles();
  const { level: confidenceLevel } = useLevel(entityType, 'confidence', confidence);
  const style = variant === 'inList' ? classes.chipInList : classes.chip;

  return (
    <Tag
      label={confidenceLevel.label}
      color={confidenceLevel.color}
    />
  );
};

export default ItemConfidence;
