import React, { FunctionComponent } from 'react';
import { SxProps, useTheme } from '@mui/material/styles';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { chipInListBasicStyle } from '../utils/chipStyle';
import Tag from '@common/tag/Tag';
import type { Theme } from './Theme';

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
  chipHigh: {
    textTransform: 'uppercase',
    borderRadius: 4,
    width: 150,
    fontSize: 18,
    lineHeight: '18px',
    height: 38,
    marginLeft: 20,
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

interface ItemSeverityProps {
  label: string;
  severity?: string | null;
  variant?: 'inList' | 'high';
}

const computeSeverityStyle = (severity: string | undefined | null) => {
  switch (severity?.toLowerCase()) {
    case 'low':
      return inlineStyles.green;
    case 'medium':
      return inlineStyles.blue;
    case 'high':
      return inlineStyles.orange;
    case 'critical':
      return inlineStyles.red;
    default:
      return inlineStyles.blueGrey;
  }
};

const ItemSeverity: FunctionComponent<ItemSeverityProps> = ({
  label,
  severity,
  variant,
}) => {
  const theme = useTheme<Theme>();
  const classes = useStyles();
  let style = classes.chip;
  if (variant === 'inList') {
    style = classes.chipInList;
  }
  if (variant === 'high') {
    style = classes.chipHigh;
  }
  const classStyle = computeSeverityStyle(severity);

  console.log('severity', severity);
  let severityColor = theme.palette.severity.default;
  // const computeSeverityStyle = (priority: string | undefined | null) => {
  switch (severity?.toLowerCase()) {
    case 'low':
      severityColor = theme.palette.severity.low;
      break;
    case 'medium':
      severityColor = theme.palette.severity.medium;
      break;
      // return inlineStyles.blue;
    case 'high':
      severityColor = theme.palette.severity.high;
      break; // return inlineStyles.orange;
    case 'critical':
      severityColor = theme.palette.severity.critical;
      break;
      // return inlineStyles.red;
    default:
      severityColor = theme.palette.severity.default;
      break;
        // return inlineStyles.blueGrey;
  }

  // return (
  //   <Chip classes={{ root: style }} style={classStyle} label={label} />
  // );

  const sxStyle: SxProps = {
    textTransform: 'lowercase',
    '& :first-letter': {
      textTransform: 'uppercase',
    },
  };

  return <Tag label={label} color={severityColor} sx={sxStyle} />;
};

// return (
//   <Chip classes={{ root: style }} style={classStyle} label={label} />
export default ItemSeverity;
