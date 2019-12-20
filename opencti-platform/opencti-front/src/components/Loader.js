import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';

const styles = () => ({
  container: {
    width: '100vh',
    height: 'calc(100vh-180px)',
  },
  containerInElement: {
    width: '100%',
    height: '100%',
    display: 'table',
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
  loaderInElement: {
    width: '100%',
    margin: 0,
    padding: 0,
    display: 'table-cell',
    verticalAlign: 'middle',
    textAlign: 'center',
  },
  loaderCircle: {
    display: 'inline-block',
  },
});

class Loader extends Component {
  render() {
    const { classes, variant, withRightPadding } = this.props;
    return (
      <div
        className={
          variant === 'inElement'
            ? classes.containerInElement
            : classes.container
        }
        style={
          variant === 'inElement'
            ? { paddingRight: withRightPadding ? 220 : 0 }
            : {}
        }
      >
        <div
          className={
            variant === 'inElement' ? classes.loaderInElement : classes.loader
          }
          style={
            variant !== 'inElement'
              ? { paddingRight: withRightPadding ? 100 : 0 }
              : {}
          }
        >
          <CircularProgress
            size={variant === 'inElement' ? 40 : 80}
            thickness={1}
            className={this.props.classes.loaderCircle}
          />
        </div>
      </div>
    );
  }
}

Loader.propTypes = {
  classes: PropTypes.object.isRequired,
  variant: PropTypes.string,
  withRightPadding: PropTypes.bool,
};

export default withStyles(styles)(Loader);
