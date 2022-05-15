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
    width: 150,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 150,
  },
});

const inlineStyles = {
  white: {
    backgroundColor: '#ffffff',
    color: '#2b2b2b',
  },
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  darkGreen: {
    backgroundColor: 'rgba(27,94,32, 0.08)',
    color: '#1b5e20',
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
    backgroundColor: '#607d8b',
  },
};

const ItemReliability = (props) => {
  const { classes, label, reliability, variant } = props;
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  switch (reliability) {
    case 'A':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.darkGreen}
          label={label}
        />
      );
    case 'B':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.green}
          label={label}
        />
      );
    case 'C':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blue}
          label={label}
        />
      );
    case 'D':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={label}
        />
      );
    case 'E':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.red}
          label={label}
        />
      );
    case 'F':
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blueGrey}
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

ItemReliability.propTypes = {
  classes: PropTypes.object.isRequired,
  reliability: PropTypes.string,
  label: PropTypes.string,
  variant: PropTypes.string,
};

export default withStyles(styles)(ItemReliability);
