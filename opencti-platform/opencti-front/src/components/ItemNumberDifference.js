import React, { Component } from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { ArrowUpward, ArrowDownward, ArrowForward } from '@material-ui/icons';

import inject18n from './i18n';

const styles = () => ({
  diff: {
    float: 'left',
    margin: '18px 0 0 10px',
    fontSize: 13,
  },
  diffDescription: {
    margin: '5px 0 0 10px',
    float: 'left',
  },
  diffIcon: {
    float: 'left',
  },
  diffNumber: {
    marginTop: 5,
    float: 'left',
  },
});

const inlineStyles = {
  green: {
    color: '#4caf50',
  },
  red: {
    color: '#f44336',
  },
  blueGrey: {
    color: '#607d8b',
  },
};

class ItemNumberDifference extends Component {
  render() {
    const {
      t, difference, classes, description,
    } = this.props;
    if (difference < 0) {
      return (
        <div className={classes.diff}>
          <ArrowDownward
            color="inherit"
            classes={{ root: classes.diffIcon }}
            style={inlineStyles.red}
          />
          <div className={classes.diffNumber} style={inlineStyles.red}>
            {difference}
          </div>
          <div className={classes.diffDescription}>({t(description)})</div>
        </div>
      );
    }
    if (difference === 0) {
      return (
        <div className={classes.diff}>
          <ArrowForward
            color="inherit"
            classes={{ root: classes.diffIcon }}
            style={inlineStyles.blueGrey}
          />
          <div className={classes.diffNumber} style={inlineStyles.blueGrey}>
            {difference}
          </div>
          <div className={classes.diffDescription}>({t(description)})</div>
        </div>
      );
    }
    return (
      <div className={classes.diff}>
        <ArrowUpward
          color="inherit"
          classes={{ root: classes.diffIcon }}
          style={inlineStyles.green}
        />
        <div className={classes.diffNumber} style={inlineStyles.green}>
          {difference}
        </div>
        <div className={classes.diffDescription}>({t(description)})</div>
      </div>
    );
  }
}

ItemNumberDifference.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  difference: PropTypes.number,
  description: PropTypes.string.isRequired,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ItemNumberDifference);
