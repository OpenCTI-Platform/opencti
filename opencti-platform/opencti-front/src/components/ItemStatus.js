import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import { compose } from 'ramda';
import inject18n from './i18n';
import { hexToRGB } from '../utils/Colors';

const styles = () => ({
  chip: {
    fontSize: 12,
    lineHeight: '12px',
    height: 25,
    marginRight: 7,
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 130,
  },
  chipInList: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    float: 'left',
    textTransform: 'uppercase',
    borderRadius: '0',
    width: 130,
  },
});

class ItemStatus extends Component {
  render() {
    const {
      classes, t, status, variant, disabled,
    } = this.props;
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    if (status) {
      return (
        <Chip
          classes={{ root: style }}
          variant="outlined"
          label={t(`status_${status.template.name}`)}
          style={{
            color: status.template.color,
            borderColor: status.template.color,
            backgroundColor: hexToRGB(status.template.color),
          }}
        />
      );
    }
    return (
      <Chip
        classes={{ root: style }}
        variant="outlined"
        label={disabled ? t('Disabled') : t('Unknown')}
      />
    );
  }
}

ItemStatus.propTypes = {
  classes: PropTypes.object.isRequired,
  status: PropTypes.object,
  variant: PropTypes.string,
  t: PropTypes.func,
  disabled: PropTypes.bool,
};

export default compose(inject18n, withStyles(styles))(ItemStatus);
