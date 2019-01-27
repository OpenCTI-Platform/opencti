import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos, Public } from '@material-ui/icons';
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

class TopMenuThreatActor extends Component {
  render() {
    const {
      t, location, match: { params: { threatActorId } }, classes,
    } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/knowledge/threatActors' variant='contained' size="small"
                color='inherit' classes={{ root: classes.buttonHome }}>
          <Public className={classes.icon} fontSize='small'/>
          {t('Threat actors')}
        </Button>
        <ArrowForwardIos color='inherit' classes={{ root: classes.arrow }}/>
        <Button component={Link} to={`/dashboard/knowledge/threat_actors/${threatActorId}`} variant={location.pathname === `/dashboard/knowledge/threat_actors/${threatActorId}` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/knowledge/threat_actors/${threatActorId}` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Overview')}
        </Button>
        <Button component={Link} to={`/dashboard/knowledge/threat_actors/${threatActorId}/reports`} variant={location.pathname === `/dashboard/knowledge/threat_actors/${threatActorId}/reports` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/knowledge/threat_actors/${threatActorId}/reports` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Reports')}
        </Button>
        <Button component={Link} to={`/dashboard/knowledge/threat_actors/${threatActorId}/knowledge`} variant={location.pathname.includes(`/dashboard/knowledge/threat_actors/${threatActorId}/knowledge`) ? 'contained' : 'text'} size="small"
                color={location.pathname.includes(`/dashboard/knowledge/threat_actors/${threatActorId}/knowledge`) ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Knowledge')}
        </Button>
        <Button component={Link} to={`/dashboard/knowledge/threat_actors/${threatActorId}/observables`} variant={location.pathname === `/dashboard/knowledge/threat_actors/${threatActorId}/observables` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/knowledge/threat_actors/${threatActorId}/observables` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Observables')}
        </Button>
      </div>
    );
  }
}

TopMenuThreatActor.propTypes = {
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
)(TopMenuThreatActor);
