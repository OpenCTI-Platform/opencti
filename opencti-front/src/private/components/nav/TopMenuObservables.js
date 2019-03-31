import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  button: {
    marginRight: theme.spacing.unit,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
});

class TopMenuReports extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/observables/all"
          variant={
            location.pathname === '/dashboard/observables/all'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/all'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('All observables')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/domains"
          variant={
            location.pathname === '/dashboard/observables/domains'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/domains'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Domains')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/ipv4"
          variant={
            location.pathname === '/dashboard/observables/ipv4'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/ipv4'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('IPv4 addresses')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/ipv6"
          variant={
            location.pathname === '/dashboard/observables/ipv6'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/ipv6'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('IPv6 addresses')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/url"
          variant={
            location.pathname === '/dashboard/observables/url'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/url'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('URL / URI')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/emails"
          variant={
            location.pathname === '/dashboard/observables/emails'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/emails'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Email addresses')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/mutex"
          variant={
            location.pathname === '/dashboard/observables/mutex'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/mutex'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Mutex')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observables/files"
          variant={
            location.pathname === '/dashboard/observables/files'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/observables/files'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('File hashes')}
        </Button>
      </div>
    );
  }
}

TopMenuReports.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuReports);
