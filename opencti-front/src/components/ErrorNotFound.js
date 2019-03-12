import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import Particles from 'react-particles-js';
import { compose } from 'ramda';
import inject18n from './i18n';

const styles = theme => ({
  container: {
    width: '100vw',
    height: 'calc(100vh-180px)',
  },
  particlesContainer: {
    position: 'absolute',
    top: 0,
    left: 0,
    zIndex: 10,
    width: '99%',
    height: '99%',
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
  }
});

class ErrorNotFound extends Component {
  render() {
    const { t, classes, variant } = this.props;
    return (
      <div className={variant === 'inside' ? classes.containerInside : classes.container}>
        <Particles
          className={classes.particlesContainer}
          params={{
            particles: {
              move: {
                enable: false,
              },
              number: {
                value: 80,
              },
              size: {
                value: 2,
              },
            },
          }}
        />
        <div className={classes.loader}>
          <span className={classes.error}>
            {t('This feature is not available yet.')}
          </span>
        </div>
      </div>
    );
  }
}

ErrorNotFound.propTypes = {
  variant: PropTypes.string,
  history: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withStyles(styles),
)(ErrorNotFound);
