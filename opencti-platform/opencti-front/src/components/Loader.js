import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';

const styles = () => ({
  container: {
    width: '100vh',
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
});

class Loader extends Component {
  render() {
    const { classes, variant } = this.props;
    if (variant === 'inElement') {
      return (
        <div style={{ display: 'table', height: '100%', width: '100%' }}>
          <span
            style={{
              display: 'table-cell',
              verticalAlign: 'middle',
              textAlign: 'center',
            }}
          >
            <CircularProgress size={80} thickness={2} />
          </span>
        </div>
      );
    }
    return (
      <div className={classes.container}>
        <div className={classes.loader} style={{ paddingRight: variant === 'withRightPadding' ? 240 : 0 }}>
          <CircularProgress
            size={80}
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
};

export default withStyles(styles)(Loader);
