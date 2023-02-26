import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import ChevronRightIcon from '@material-ui/icons/ChevronRight';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  root: {
    marginTop: 0,
  },
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '4px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  button: {
    marginRight: theme.spacing(1),
    padding: '4px 25px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuAssets extends Component {
  handleChangeAssetName() {
    const { location } = this.props;
    if (location.pathname === '/defender HQ/assets/devices'
      || location.pathname === '/defender HQ/assets/software'
      || location.pathname === '/defender HQ/assets/network'
      || location.pathname === '/defender HQ/assets/information_systems') {
      return this.renderMenuAssets();
    }
    if (location.pathname.includes('/defender HQ/assets/devices/')) {
      return this.renderMenuDevice();
    }
    if (location.pathname.includes('/defender HQ/assets/software/')) {
      return this.renderMenuSoftware();
    }
    if (location.pathname.includes('/defender HQ/assets/network/')) {
      return this.renderMenuNetwork();
    }
    if (location.pathname.includes('/defender HQ/assets/information_systems/')) {
      return this.renderMenuInformationSystems();
    }
    return 'Default';
  }

  render() {
    return this.handleChangeAssetName();
  }

  renderMenuAssets() {
    const { t, location, classes } = this.props;
    return (
      <div className={classes.root}>
        <Button
          component={Link}
          to="/defender HQ/assets"
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Asset')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to="/defender HQ/assets/devices"
          variant={
            location.pathname.includes('/defender HQ/assets/devices')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/defender HQ/assets/devices')
              ? 'secondary'
              : 'default'
          }
          classes={{ root: classes.button }}
          data-cy='asset devices'
        >
          {t('Devices')}
        </Button>
        <Button
          component={Link}
          to="/defender HQ/assets/network"
          variant={
            location.pathname.includes('/defender HQ/assets/network')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/defender HQ/assets/network')
              ? 'secondary'
              : 'default'
          }
          classes={{ root: classes.button }}
          data-cy='asset networks'
        >
          {t('Network')}
        </Button>
        <Button
          component={Link}
          to="/defender HQ/assets/software"
          variant={
            location.pathname.includes('/defender HQ/assets/software')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/defender HQ/assets/software'
              ? 'secondary'
              : 'default'
          }
          classes={{ root: classes.button }}
          data-cy='asset software'
        >
          {t('Software')}
        </Button>
        <Button
          component={Link}
          to="/defender HQ/assets/information_systems"
          variant={
            location.pathname.includes('/defender HQ/assets/information_systems')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/defender HQ/assets/information_systems'
              ? 'secondary'
              : 'default'
          }
          classes={{ root: classes.button }}
          data-cy='asset information_systems'
        >
          {t('Information Systems')}
        </Button>
      </div>
    );
  }

  renderMenuDevice() {
    const { t, classes } = this.props;
    return (
      <div className={classes.root}>
        <Button
          component={Link}
          to="/defender HQ/assets/devices"
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Devices')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          variant='contained'
          size="small"
          color='secondary'
          classes={{ root: classes.button }}
          data-cy='asset overview'
        >
          {t('Overview')}
        </Button>
      </div>
    );
  }

  renderMenuNetwork() {
    const { t, classes } = this.props;
    return (
      <div className={classes.root}>
        <Button
          component={Link}
          to="/defender HQ/assets/network"
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Network')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          variant='contained'
          size="small"
          color='secondary'
          classes={{ root: classes.button }}
          data-cy='asset overview'
        >
          {t('Overview')}
        </Button>
      </div>
    );
  }

  renderMenuSoftware() {
    const { t, classes } = this.props;
    return (
      <div className={classes.root}>
        <Button
          component={Link}
          to="/defender HQ/assets/software"
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Software')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          variant='contained'
          size="small"
          color='secondary'
          classes={{ root: classes.button }}
          data-cy='asset overview'
        >
          {t('Overview')}
        </Button>
      </div>
    );
  }

  renderMenuInformationSystems() {
    const {
      t,
      classes,
      location,
      match: {
        params: { informationSystemId },
      },
    } = this.props;
    return (
      <div className={classes.root}>
        <Button
          component={Link}
          to='/defender HQ/assets/information_systems'
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Information Systems')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          size="small"
          data-cy='asset overview'
          classes={{ root: classes.button }}
          variant={
            location.pathname
              === `/defender HQ/assets/information_systems/${informationSystemId}`
              ? 'contained'
              : 'text'
          }
          color={
            location.pathname
              === `/defender HQ/assets/information_systems/${informationSystemId}`
              ? 'secondary'
              : 'inherit'
          }
          to={`/defender HQ/assets/information_systems/${informationSystemId}`}
        >
          {t('Overview')}
        </Button>
        <Button
          // component={Link}
          size="small"
          data-cy='asset analysis'
          classes={{ root: classes.button }}
          variant={
            location.pathname
              === `/defender HQ/assets/information_systems/${informationSystemId}/analysis`
              ? 'contained'
              : 'text'
          }
          color={
            location.pathname
              === `/defender HQ/assets/information_systems/${informationSystemId}/analysis`
              ? 'secondary'
              : 'inherit'
          }
          // to={`/defender HQ/assets/information_systems/${informationSystemId}/analysis`}
        >
          {t('Analysis')}
        </Button>
      </div>
    );
  }
}

TopMenuAssets.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuAssets);
