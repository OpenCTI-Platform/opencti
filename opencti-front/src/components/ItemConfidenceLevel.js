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
  },
  chipInList: {
    fontSize: 12,
    height: 20,
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
  blue: {
    backgroundColor: '#3f51b5',
  },
  red: {
    backgroundColor: '#f44336',
  },
  orange: {
    backgroundColor: '#ff9800',
  },
  blueGrey: {
    backgroundColor: '#607d8b',
    fontStyle: 'italic',
  },
};

class ItemConfidenceLevel extends Component {
  render() {
    const {
      t, level, classes, variant,
    } = this.props;
    let style = classes.chip;
    switch (variant) {
      case 'inList':
        style = classes.chipInList;
        break;
      default:
        style = classes.chip;
    }

    switch (level) {
      case 1:
        return <Chip classes={{ root: style }} style={inlineStyles.red} label={t('Very low')}/>;
      case 2:
        return <Chip classes={{ root: style }} style={inlineStyles.orange} label={t('Low')}/>;
      case 3:
        return <Chip classes={{ root: style }} style={inlineStyles.blue} label={t('Medium')}/>;
      case 4:
        return <Chip classes={{ root: style }} style={inlineStyles.green} label={t('High')}/>;
      case 5:
        return <Chip classes={{ root: style }} style={inlineStyles.darkGreen} label={t('Very high')}/>;
      case 99:
        return <Chip classes={{ root: style }} style={inlineStyles.blueGrey} label={t('Inferred')}/>;
      default:
        return <Chip classes={{ root: style }} style={inlineStyles.blue} label={t('Medium')}/>;
    }
  }
}

ItemConfidenceLevel.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  level: PropTypes.number,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ItemConfidenceLevel);
