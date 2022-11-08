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
  severity?: string;
  variant?: 'inList';
}

const ItemSeverity: FunctionComponent<ItemSeverityProps> = ({
  label,
  severity,
  variant,
}) => {
  const classes = useStyles();
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  switch (severity) {
    case 'low':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.green}
          label={label}
        />
      );
    case 'medium':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blue}
          label={label}
        />
      );
    case 'high':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'critical':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.red}
          label={label}
        />
      );
    default:
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blueGrey}
          label={label}
        />
      );
  }
};

export default ItemSeverity;
