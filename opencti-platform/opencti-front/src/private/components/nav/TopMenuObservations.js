import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import {
  HexagonOutline,
  ShieldSearch,
  ServerNetwork,
  ArchiveOutline,
} from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuObservations extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/observations/observables"
          variant={
            location.pathname.includes('/dashboard/observations/observables')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/observations/observables')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <HexagonOutline className={classes.icon} fontSize="small" />
          {t('Observables')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observations/artifacts"
          variant={
            location.pathname.includes('/dashboard/observations/artifacts')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/observations/artifacts')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ArchiveOutline className={classes.icon} fontSize="small" />
          {t('Artifacts')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observations/indicators"
          variant={
            location.pathname.includes('/dashboard/observations/indicators')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/observations/indicators')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ShieldSearch className={classes.icon} fontSize="small" />
          {t('Indicators')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/observations/infrastructures"
          variant={
            location.pathname.includes(
              '/dashboard/observations/infrastructures',
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              '/dashboard/observations/infrastructures',
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <ServerNetwork className={classes.icon} fontSize="small" />
          {t('Infrastructures')}
        </Button>
      </div>
    );
  }
}

TopMenuObservations.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuObservations);
