import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 80,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
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
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    if (status === true) {
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.green}
          label={label}
        />
      );
    }
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.orange}
        label={label}
      />
    );
  }
}

ItemMarking.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.bool,
  label: PropTypes.string,
  variant: PropTypes.string,
};

export default withStyles(styles)(ItemMarking);
