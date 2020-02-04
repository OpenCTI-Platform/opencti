import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';

const styles = () => ({
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
  },
});

const inlineStyles = {
  white: {
    backgroundColor: '#ffffff',
    color: '#2b2b2b',
  },
  green: {
    backgroundColor: '#2e7d32',
  },
  darkGreen: {
    backgroundColor: '#1b5e20',
  },
  red: {
    backgroundColor: '#f44336',
  },
  orange: {
    backgroundColor: '#ff9800',
  },
  blueGrey: {
    backgroundColor: '#607d8b',
  },
};

class ItemReliability extends Component {
  render() {
    const {
      classes, label, reliability, variant,
    } = this.props;
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
  }
}

ItemReliability.propTypes = {
  classes: PropTypes.object.isRequired,
  reliability: PropTypes.number,
  label: PropTypes.string,
  variant: PropTypes.string,
};

export default withStyles(styles)(ItemReliability);
