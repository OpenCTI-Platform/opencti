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
    marginRight: 15,
  },
});

class ItemYears extends Component {
  render() {
    const {
      years, classes, variant, disabled,
    } = this.props;
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    return (
      <Chip
        classes={{ root: style }}
        color={disabled ? 'default' : 'secondary'}
        label={years}
      />
    );
  }
}

ItemYears.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  years: PropTypes.string,
  disabled: PropTypes.bool,
};

export default withStyles(styles)(ItemYears);
