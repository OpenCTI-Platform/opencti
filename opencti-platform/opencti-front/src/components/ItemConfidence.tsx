import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { useLevel } from '../utils/hooks/useScale';
import { hexToRGB } from '../utils/Colors';
import { chipInListBasicStyle } from '../utils/chipStyle';

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
  label: {
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
  },
}));

interface ItemConfidenceProps {
  confidence: number | null | undefined,
  variant?: string,
  entityType: string,
}

const ItemConfidence: FunctionComponent<ItemConfidenceProps> = ({ confidence, variant, entityType }) => {
  const classes = useStyles();
  const { level: confidenceLevel } = useLevel(entityType, 'confidence', confidence);
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  return (
    <Tooltip title={confidenceLevel.label}>
      <Chip
        classes={{ root: style, label: classes.label }}
        style={{
          color: confidenceLevel.color,
          borderColor: confidenceLevel.color,
          backgroundColor: hexToRGB(confidenceLevel.color),
        }}
        label={confidenceLevel.label}
      />
    </Tooltip>
  );
};

export default ItemConfidence;
