import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos } from '@material-ui/icons';
import { Diamond } from 'mdi-material-ui';
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

class TopMenuIntrusionSet extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { intrusionSetId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/threats/intrusion_sets"
          variant="contained"
          size="small"
          color="inherit"
          classes={{ root: classes.buttonHome }}
        >
          <Diamond className={classes.icon} fontSize="small" />
          {t('Intrusion sets')}
        </Button>
        <ArrowForwardIos color="inherit" classes={{ root: classes.arrow }} />
        <Button
          component={Link}
          to={`/dashboard/threats/intrusion_sets/${intrusionSetId}`}
          variant={
            location.pathname
            === `/dashboard/threats/intrusion_sets/${intrusionSetId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/intrusion_sets/${intrusionSetId}`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/reports`}
          variant={
            location.pathname
            === `/dashboard/threats/intrusion_sets/${intrusionSetId}/reports`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/intrusion_sets/${intrusionSetId}/reports`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Reports')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/threats/intrusion_sets/${intrusionSetId}/knowledge`,
            )
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/observables`}
          variant={
            location.pathname.includes(
              `/dashboard/threats/intrusion_sets/${intrusionSetId}/observables`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/threats/intrusion_sets/${intrusionSetId}/observables`,
            )
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Observables')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/intrusion_sets/${intrusionSetId}/files`}
          variant={
            location.pathname
            === `/dashboard/threats/intrusion_sets/${intrusionSetId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/intrusion_sets/${intrusionSetId}/files`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Files')}
        </Button>
      </div>
    );
  }
}

TopMenuIntrusionSet.propTypes = {
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
)(TopMenuIntrusionSet);
