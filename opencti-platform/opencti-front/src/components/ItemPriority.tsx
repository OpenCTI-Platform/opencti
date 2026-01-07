import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useTheme } from '@mui/material/styles';
import { chipInListBasicStyle } from '../utils/chipStyle';
import type { Theme } from './Theme';
import Tag from '@common/tag/Tag';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 80,
  },
  chipInList: {
    ...chipInListBasicStyle,
    textTransform: 'uppercase',
    width: 80,
  },
}));

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
  orange: {
    backgroundColor: 'rgba(255, 152, 0, 0.08)',
    color: '#ff9800',
  },
  blueGrey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
    fontStyle: 'italic',
  },
};

interface ItemPriorityProps {
  label: string;
  priority?: string | null;
  variant?: 'inList';
}

const computePriorityStyle = (priority: string | undefined | null) => {
  switch (priority) {
    case 'P4':
      return inlineStyles.green;
    case 'P3':
      return inlineStyles.blue;
    case 'P2':
      return inlineStyles.orange;
    case 'P1':
      return inlineStyles.red;
    default:
      return inlineStyles.blueGrey;
  }
};

const ItemPriority: FunctionComponent<ItemPriorityProps> = ({
  label,
  priority,
  variant,
}) => {
  const theme = useTheme<Theme>();
  const classes = useStyles();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  const classStyle = computePriorityStyle(priority);

  let priorityColor = theme.palette.severity.info;
  switch (priority) {
    case 'P4':
      priorityColor = theme.palette.severity.low; //  inlineStyles.green;
      break;
    case 'P3':
      priorityColor = theme.palette.severity.medium; // inlineStyles.blue;
      break;
    case 'P2':
      priorityColor = theme.palette.severity.high; // inlineStyles.orange;
      break;
    case 'P1':
      priorityColor = theme.palette.severity.critical; // nlineStyles.red;
      break;
    default:
      priorityColor = theme.palette.severity.default; // inlineStyles.blueGrey;
      break;
  }

  return <Tag label={label} color={priorityColor} />;

  // return <Chip classes={{ root: style }} style={classStyle} label={label} />;
};

export default ItemPriority;
