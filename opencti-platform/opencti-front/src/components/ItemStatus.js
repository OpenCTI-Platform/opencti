import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';

const styles = () => ({
  chip: {
    fontSize: 12,
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
  },
  chipInList: {
    fontSize: 12,
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: '0',
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
  blue: {
    backgroundColor: 'rgba(92, 123, 245, 0.08)',
    color: '#5c7bf5',
  },
  grey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
  },
  orange: {
    backgroundColor: 'rgba(255, 152, 0, 0.08)',
    color: '#ff9800',
  },
};

class ItemMarking extends Component {
  render() {
    const {
      classes, label, status, variant,
    } = this.props;
    const style = (variant === 'inList') ? classes.chipInList : classes.chip;
    switch (status) {
      case 0:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.orange}
            label={label}
          />
        );
      case 1:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={label}
          />
        );
      case 2:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.green}
            label={label}
          />
        );
      case 3:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.grey}
            label={label}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={label}
          />
        );
    }
  }
}

ItemMarking.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.number,
  label: PropTypes.string,
  variant: PropTypes.string,
};

export default withStyles(styles)(ItemMarking);
