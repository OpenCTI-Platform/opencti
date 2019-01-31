import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos, Explore, BugReport } from '@material-ui/icons';
import {
  ChessKnight,
  LockPattern,
  SortAscending,
  Target,
  TagMultiple,
} from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  buttonHome: {
    marginRight: theme.spacing.unit * 2,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
    transition: 'background-color 0.1s ease',
    color: '#666666',
    backgroundColor: '#ffffff',
    '&:hover': {
      color: '#666666',
      backgroundColor: '#c4c4c4',
    },
  },
  buttonHomeActive: {
    marginRight: theme.spacing.unit * 2,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
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

class TopMenuExplore extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/explore' variant={location.pathname === '/dashboard/explore' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore' ? 'primary' : 'inherit'} classes={{ root: location.pathname === '/dashboard/explore' ? classes.buttonHomeActive : classes.buttonHome }}>
          <Explore className={classes.icon} fontSize='small'/>
          {t('Explore')}
        </Button>
        <ArrowForwardIos color='inherit' classes={{ root: classes.arrow }}/>
        <Button component={Link} to='/dashboard/explore/victimology' variant={location.pathname === '/dashboard/explore/victimology' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore/victimology' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Target className={classes.icon} fontSize='small'/>
          {t('Victimology')}
        </Button>
        <Button component={Link} to='/dashboard/explore/campaigns' variant={location.pathname === '/dashboard/explore/campaigns' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore/campaigns' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <ChessKnight className={classes.icon} fontSize='small'/>
          {t('Campaigns')}
        </Button>
        <Button component={Link} to='/dashboard/explore/ttp' variant={location.pathname === '/dashboard/explore/ttp' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore/ttp' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <LockPattern className={classes.icon} fontSize='small'/>
          {t('Attack patterns')}
        </Button>
        <Button component={Link} to='/dashboard/explore/killchains' variant={location.pathname === '/dashboard/explore/killchains' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore/killchains' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <SortAscending className={classes.icon} fontSize='small'/>
          {t('Kill chains')}
        </Button>
        <Button component={Link} to='/dashboard/explore/vulnerabilities' variant={location.pathname === '/dashboard/explore/vulnerabilities' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore/vulnerabilities' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <BugReport className={classes.icon} fontSize='small'/>
          {t('Vulnerabilities')}
        </Button>
        <Button component={Link} to='/dashboard/explore/observables' variant={location.pathname === '/dashboard/explore/observables' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/explore/observables' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <TagMultiple className={classes.icon} fontSize='small'/>
          {t('Observables')}
        </Button>
      </div>
    );
  }
}

TopMenuExplore.propTypes = {
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
)(TopMenuExplore);
