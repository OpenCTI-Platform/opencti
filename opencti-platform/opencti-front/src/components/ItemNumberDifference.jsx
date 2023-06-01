import React from 'react';
import { compose } from 'ramda';
import * as PropTypes from 'prop-types';
import withStyles from '@mui/styles/withStyles';
import { ArrowUpward, ArrowDownward, ArrowForward } from '@mui/icons-material';

import inject18n from './i18n';

const styles = (theme) => ({
  diff: {
    float: 'left',
    margin: '23px 0 0 10px',
    padding: '2px 5px 2px 5px',
    fontSize: 12,
  },
  diffDescription: {
    margin: '2px 0 0 10px',
    float: 'left',
    fontSize: 9,
    color: theme.palette.text.primary,
  },
  diffIcon: {
    float: 'left',
    margin: '1px 5px 0 0',
    fontSize: 13,
  },
  diffNumber: {
    float: 'left',
  },
});

const inlineStyles = {
  green: {
    backgroundColor: 'rgba(76, 175, 80, 0.08)',
    color: '#4caf50',
  },
  red: {
    backgroundColor: 'rgba(244, 67, 54, 0.08)',
    color: '#f44336',
  },
  blueGrey: {
    backgroundColor: 'rgba(96, 125, 139, 0.08)',
    color: '#607d8b',
  },
};

const ItemNumberDifference = (props) => {
  const { t, difference, classes, description } = props;
  if (difference < 0) {
    return (
      <div className={classes.diff} style={inlineStyles.red}>
        <ArrowDownward color="inherit" classes={{ root: classes.diffIcon }} />
        <div className={classes.diffNumber}>{difference}</div>
        {description ? (
          <div className={classes.diffDescription}>({t(description)})</div>
        ) : (
          ''
        )}
      </div>
    );
  }
  if (difference === 0) {
    return (
      <div className={classes.diff} style={inlineStyles.blueGrey}>
        <ArrowForward color="inherit" classes={{ root: classes.diffIcon }} />
        <div className={classes.diffNumber}>{difference}</div>
        {description ? (
          <div className={classes.diffDescription}>({t(description)})</div>
        ) : (
          ''
        )}
      </div>
    );
  }
  return (
    <div className={classes.diff} style={inlineStyles.green}>
      <ArrowUpward color="inherit" classes={{ root: classes.diffIcon }} />
      <div className={classes.diffNumber}>{difference}</div>
      {description ? (
        <div className={classes.diffDescription}>({t(description)})</div>
      ) : (
        ''
      )}
    </div>
  );
};

ItemNumberDifference.propTypes = {
  classes: PropTypes.object.isRequired,
  t: PropTypes.func,
  difference: PropTypes.number,
  description: PropTypes.string.isRequired,
};

export default compose(inject18n, withStyles(styles))(ItemNumberDifference);
