import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';

const styles = () => ({
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
});

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

const ItemCriticality = (props) => {
  const { classes, label, criticality, variant } = props;
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  switch (criticality) {
    case 'Low':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.green}
          label={label}
        />
      );
    case 'Medium':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blue}
          label={label}
        />
      );
    case 'High':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'Critical':
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

ItemCriticality.propTypes = {
  classes: PropTypes.object.isRequired,
  reliability: PropTypes.string,
  label: PropTypes.string,
  variant: PropTypes.string,
};

export default withStyles(styles)(ItemCriticality);
