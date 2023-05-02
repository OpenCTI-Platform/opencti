import React from 'react';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import Chip from '@mui/material/Chip';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 15,
  },
});

const ItemYears = (props) => {
  const { years, classes, variant, disabled } = props;
  const style = variant === 'inList' ? classes.chipInList : classes.chip;
  return (
    <Chip
      classes={{ root: style }}
      color={disabled ? 'default' : 'secondary'}
      label={years === '1970 - 5138' ? '-' : years}
    />
  );
};

ItemYears.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  years: PropTypes.string,
  disabled: PropTypes.bool,
};

export default withStyles(styles)(ItemYears);
