import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';
import Security, { SETTINGS_SETACCESSES, SETTINGS_SETMARKINGS } from '../../../utils/Security';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuSettings extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button component={Link} to="/dashboard/settings"
          variant={
            location.pathname === '/dashboard/settings'
            || location.pathname === '/dashboard/settings/about'
            || location.pathname === '/dashboard/settings/inferences'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/settings'
            || location.pathname === '/dashboard/settings/about'
            || location.pathname === '/dashboard/settings/inferences'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}>
          {t('Parameters')}
        </Button>
        <Security needs={[SETTINGS_SETACCESSES]}>
            <Button component={Link} to="/dashboard/settings/accesses"
              variant={
                location.pathname.includes('/dashboard/settings/accesses')
                  ? 'contained'
                  : 'text'
              }
              size="small"
              color={
                location.pathname.includes('/dashboard/settings/accesses')
                  ? 'primary'
                  : 'inherit'
              }
              classes={{ root: classes.button }}>
              {t('Accesses')}
            </Button>
        </Security>
        <Security needs={[SETTINGS_SETMARKINGS]}>
            <Button component={Link} to="/dashboard/settings/marking"
              variant={
                location.pathname.includes('/dashboard/settings/marking')
                  ? 'contained'
                  : 'text'
              }
              size="small"
              color={
                location.pathname === '/dashboard/settings/marking'
                  ? 'primary'
                  : 'inherit'
              }
              classes={{ root: classes.button }}>
              {t('Marking')}
            </Button>
        </Security>
        <Button
          component={Link}
          to="/dashboard/settings/killchains"
          variant={
            location.pathname.includes('/dashboard/settings/killchains')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/settings/killchains')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Kill chain phases')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/settings/attributes"
          variant={
            location.pathname.includes('/dashboard/settings/attributes')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/settings/attributes')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Tags & Attributes')}
        </Button>
      </div>
    );
  }
}

TopMenuSettings.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuSettings);
