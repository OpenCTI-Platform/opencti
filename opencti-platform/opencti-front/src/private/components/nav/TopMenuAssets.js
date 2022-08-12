import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';
import deviceIcon from '../../../resources/images/assets/deviceIcon.svg';
import networkIcon from '../../../resources/images/assets/networkIcon.svg';
import softwareIcon from '../../../resources/images/assets/softwareIcon.svg';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(1),
    padding: '4px 25px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
    borderRadius: '8px 8px 0px 0px',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuAssets extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
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
              : 'inherit'
          }
          classes={{ root: classes.button }}
          data-cy='asset devices'
        >
          <img src={deviceIcon} className={classes.icon} alt="" />
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
              : 'inherit'
          }
          classes={{ root: classes.button }}
          data-cy='asset networks'
        >
          <img src={networkIcon} className={classes.icon} alt="" />
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
              : 'inherit'
          }
          classes={{ root: classes.button }}
          data-cy='asset software'
        >
          <img src={softwareIcon} className={classes.icon} alt="" />
          {t('Software')}
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
