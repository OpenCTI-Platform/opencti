import React, { Component } from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Chip from '@material-ui/core/Chip';
import inject18n from './i18n';

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

class ItemConfidenceLevel extends Component {
  render() {
    const {
      t, level, classes, variant,
    } = this.props;
    const style = variant === 'inList' ? classes.chipInList : classes.chip;
    switch (level) {
      case 1:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.red}
            label={t('Low')}
          />
        );
      case 2:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.orange}
            label={t('Moderate')}
          />
        );
      case 3:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={t('Good')}
          />
        );
      case 4:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.green}
            label={t('Strong')}
          />
        );
      case 99:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blueGrey}
            label={t('Inferred')}
          />
        );
      default:
        return (
          <Chip
            classes={{ root: style }}
            style={inlineStyles.blue}
            label={t('Moderate')}
          />
        );
    }
  }
}

ItemConfidenceLevel.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  level: PropTypes.number,
};

export default compose(inject18n, withStyles(styles))(ItemConfidenceLevel);
