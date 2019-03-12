import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import {
  Person,
  AccountBalance,
  Flag,
  BugReport,
  Map,
} from '@material-ui/icons';
import { Application, CityVariant, LockPattern } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  button: {
    marginRight: theme.spacing.unit * 2,
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing.unit,
  },
});

class TopMenuSources extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/catalogs/attack_patterns' variant={location.pathname === '/dashboard/catalogs/attack_patterns' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/attack_patterns' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <LockPattern className={classes.icon} fontSize='small'/>
          {t('TTPs')}
        </Button>
        <Button component={Link} to='/dashboard/catalogs/tools' variant={location.pathname === '/dashboard/catalogs/tools' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/tools' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Application className={classes.icon} fontSize='small'/>
          {t('Tools')}
        </Button>
        <Button component={Link} to='/dashboard/catalogs/vulnerabilities' variant={location.pathname === '/dashboard/catalogs/vulnerabilities' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/vulnerabilities' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <BugReport className={classes.icon} fontSize='small'/>
          {t('Vulnerabilities')}
        </Button>
        <div style={{ paddingRight: 20, display: 'inline-block' }}>|</div>
        <Button component={Link} to='/dashboard/catalogs/regions' variant={location.pathname === '/dashboard/catalogs/regions' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/regions' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Map className={classes.icon} fontSize='small'/>
          {t('Regions')}
        </Button>
        <Button component={Link} to='/dashboard/catalogs/countries' variant={location.pathname === '/dashboard/catalogs/countries' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/countries' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Flag className={classes.icon} fontSize='small'/>
          {t('Countries')}
        </Button>
        <Button component={Link} to='/dashboard/catalogs/cities' variant={location.pathname === '/dashboard/catalogs/cities' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/cities' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <CityVariant className={classes.icon} fontSize='small'/>
          {t('Cities')}
        </Button>
        <Button component={Link} to='/dashboard/catalogs/organizations' variant={location.pathname === '/dashboard/catalogs/organizations' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/organizations' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <AccountBalance className={classes.icon} fontSize='small'/>
          {t('Organizations')}
        </Button>
        <Button component={Link} to='/dashboard/catalogs/persons' variant={location.pathname === '/dashboard/catalogs/persons' ? 'contained' : 'text'} size='small'
                color={location.pathname === '/dashboard/catalogs/persons' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          <Person className={classes.icon} fontSize='small'/>
          {t('Persons')}
        </Button>
      </div>
    );
  }
}

TopMenuSources.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuSources);
