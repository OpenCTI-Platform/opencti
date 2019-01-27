import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos } from '@material-ui/icons';
import { Fire } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  buttonHome: {
    marginRight: theme.spacing.unit * 2,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
    color: '#666666',
    backgroundColor: '#ffffff',
  },
  button: {
    marginRight: theme.spacing.unit * 2,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing.unit,
  },
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuIncident extends Component {
  render() {
    const {
      t, location, match: { params: { incidentId } }, classes,
    } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/knowledge/incidents' variant='contained' size="small"
                color='inherit' classes={{ root: classes.buttonHome }}>
          <Fire className={classes.icon} fontSize='small'/>
          {t('Incidents')}
        </Button>
        <ArrowForwardIos color='inherit' classes={{ root: classes.arrow }}/>
        <Button component={Link} to={`/dashboard/knowledge/incidents/${incidentId}`} variant={location.pathname === `/dashboard/knowledge/incidents/${incidentId}` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/knowledge/incidents/${incidentId}` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Overview')}
        </Button>
        <Button component={Link} to={`/dashboard/knowledge/incidents/${incidentId}/reports`} variant={location.pathname === `/dashboard/knowledge/incidents/${incidentId}/reports` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/knowledge/incidents/${incidentId}/reports` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Reports')}
        </Button>
        <Button component={Link} to={`/dashboard/knowledge/incidents/${incidentId}/knowledge`} variant={location.pathname.includes(`/dashboard/knowledge/incidents/${incidentId}/knowledge`) ? 'contained' : 'text'} size="small"
                color={location.pathname.includes(`/dashboard/knowledge/incidents/${incidentId}/knowledge`) ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Knowledge')}
        </Button>
        <Button component={Link} to={`/dashboard/knowledge/incidents/${incidentId}/observables`} variant={location.pathname === `/dashboard/knowledge/incidents/${incidentId}/observables` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/knowledge/incidents/${incidentId}/observables` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Observables')}
        </Button>
      </div>
    );
  }
}

TopMenuIncident.propTypes = {
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
)(TopMenuIncident);
