import React, { FunctionComponent } from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';

const useStyles = makeStyles(() => ({
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 80,
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
  variant?: 'inList';
}

const computeSeverityStyle = (severity: string | undefined | null) => {
  switch (severity) {
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
  const classes = useStyles();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  const classStyle = computeSeverityStyle(severity);
  return (
    <Chip classes={{ root: style }} style={classStyle} label={label} />
  );
};

export default ItemSeverity;
