import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import { compose } from 'ramda';

const styles = theme => ({
  container: {
    width: '100vw',
    height: 'calc(100vh-180px)',
  },
  loader: {
    width: '100%',
    margin: 0,
    padding: 0,
    position: 'absolute',
    top: '46%',
    left: 0,
    textAlign: 'center',
    zIndex: 20,
  },
  loaderCircle: {
    display: 'inline-block',
  },
  error: {
    color: theme.palette.primary.main,
    fontSize: 20,
  },
});

class NoContent extends Component {
  render() {
    const { classes, variant, message } = this.props;
    return (
      <div
        className={
          variant === 'inside' ? classes.containerInside : classes.container
        }
      >
        <div className={classes.loader}>
          <span className={classes.error}>{message}</span>
        </div>
      </div>
    );
  }
}

NoContent.propTypes = {
  variant: PropTypes.string,
  history: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  message: PropTypes.string,
};

export default compose(withStyles(styles))(NoContent);
