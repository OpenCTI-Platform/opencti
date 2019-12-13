import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withStyles } from '@material-ui/core/styles';
import CircularProgress from '@material-ui/core/CircularProgress';
import Particles from 'react-particles-js';

const styles = () => ({
  container: {
    width: '100vh',
    height: '100vh',
  },
  containerInside: {
    width: '100vh',
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
});

class LoaderWithParticles extends Component {
  render() {
    const { classes, variant } = this.props;
    return (
      <div
        className={
          variant === 'inside' ? classes.containerInside : classes.container
        }
      >
        <Particles
          className={classes.particlesContainer}
          params={{
            particles: {
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

LoaderWithParticles.propTypes = {
  variant: PropTypes.string,
  history: PropTypes.object,
  classes: PropTypes.object,
};

export default withStyles(styles)(LoaderWithParticles);
