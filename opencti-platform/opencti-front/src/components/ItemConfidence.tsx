import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import { useLevel } from '../utils/hooks/useScale';
import { hexToRGB } from '../utils/Colors';

const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    marginRight: 7,
    borderRadius: '0',
    width: 120,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    borderRadius: '0',
    width: 80,
  },
}));

interface ItemConfidenceProps {
  confidence: number | null,
  variant?: string,
  entityType: string,
}

const ItemConfidence: FunctionComponent<ItemConfidenceProps> = ({ confidence, variant, entityType }) => {
  const classes = useStyles();

  const { level: confidenceLevel } = useLevel(entityType, 'confidence', confidence);

  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  const multilineChip = {
    height: 'auto',
    '& .MuiChip-label': {
      whiteSpace: 'normal',
      padding: '4px 6px',
    },
  };
  return (
    <Chip
      classes={{ root: style }}
      sx={variant !== 'inList' ? multilineChip : {}}
      style={{
        color: confidenceLevel.color,
        borderColor: confidenceLevel.color,
        backgroundColor: hexToRGB(confidenceLevel.color),
      }}
      label={confidenceLevel.label}
    />
  );
};

export default ItemConfidence;
