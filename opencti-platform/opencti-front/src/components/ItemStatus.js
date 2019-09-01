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
    backgroundColor: '#1b5e20',
  },
  blue: {
    backgroundColor: '#283593',
  },
  grey: {
    backgroundColor: '#424242',
  },
  orange: {
    backgroundColor: '#d84315',
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
