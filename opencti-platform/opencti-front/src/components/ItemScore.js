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
    float: 'right',
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

class ItemScore extends Component {
  render() {
    const { score, classes, variant } = this.props;
    const style = (variant === 'inList') ? classes.chipInList : classes.chip;
    if (score <= 20) {
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.darkGreen}
          label={`${score}/100`}
        />
      );
    }
    if (score <= 40) {
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.blue}
          label={`${score}/100`}
        />
      );
    }
    if (score <= 60) {
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.orange}
          label={`${score}/100`}
        />
      );
    }
    if (score <= 80) {
      return (
        <Chip
          classes={{ root: style }}
          style={inlineStyles.red}
          label={`${score}/100`}
        />
      );
    }
    return (
      <Chip
        classes={{ root: style }}
        style={inlineStyles.black}
        label={`${score}/100`}
      />
    );
  }
}

ItemScore.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  score: PropTypes.number,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ItemScore);