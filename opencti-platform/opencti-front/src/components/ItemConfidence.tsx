import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import { useTheme } from '@mui/material';
import { useLevel } from '../utils/hooks/useScale';
import { hexToRGB } from '../utils/Colors';
import useAuth from '../utils/hooks/useAuth';
import ThemeDark from './ThemeDark';
import ThemeLight from './ThemeLight';

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
    fontSize: 12,
    height: 20,
    float: 'left',
    borderRadius: 4,
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
  const { me: { monochrome_labels } } = useAuth();
  const { palette: { mode } } = useTheme();
  const theme = mode === 'dark'
    ? ThemeDark()
    : ThemeLight();
  const normalColor = mode === 'dark' ? '#ffffff' : '#000000';
  const classes = useStyles();
  const { level: confidenceLevel } = useLevel(entityType, 'confidence', confidence);
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  return (
    <Tooltip title={confidenceLevel.label}>
      {monochrome_labels
        ? (
          <Chip
            classes={{ root: style, label: classes.label }}
            style={{
              color: theme.palette.chip.main,
              backgroundColor: theme.palette.background.accent,
            }}
            label={confidenceLevel.label}
          />
        ) : (
          <Chip
            classes={{ root: style, label: classes.label }}
            style={{
              color: normalColor,
              borderColor: confidenceLevel.color,
              backgroundColor: hexToRGB(confidenceLevel.color),
            }}
            label={confidenceLevel.label}
          />
        )
      }
    </Tooltip>
  );
};

export default ItemConfidence;
