import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos } from '@material-ui/icons';
import { HexagonOutline } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
    color: '#666666',
    backgroundColor: '#ffffff',
  },
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
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuObservable extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { observableId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/signatures/observables"
          variant="contained"
          size="small"
          color="inherit"
          classes={{ root: classes.buttonHome }}
        >
          <HexagonOutline className={classes.icon} fontSize="small" />
          {t('Observables')}
        </Button>
        <ArrowForwardIos color="inherit" classes={{ root: classes.arrow }} />
        <Button
          component={Link}
          to={`/dashboard/signatures/observables/${observableId}`}
          variant={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/signatures/observables/${observableId}/links`}
          variant={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}/links`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}/links`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Linked observables')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/signatures/observables/${observableId}/knowledge`}
          variant={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}/knowledge`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}/knowledge`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/signatures/observables/${observableId}/history`}
          variant={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/signatures/observables/${observableId}/history`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuObservable.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  match: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuObservable);
