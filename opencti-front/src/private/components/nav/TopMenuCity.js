import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos } from '@material-ui/icons';
import { CityVariant } from 'mdi-material-ui';
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

class TopMenuCity extends Component {
  render() {
    const {
      t, location, match: { params: { cityId } }, classes,
    } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/catalogs/cities' variant='contained' size="small"
                color='inherit' classes={{ root: classes.buttonHome }}>
          <CityVariant className={classes.icon} fontSize='small'/>
          {t('Cities')}
        </Button>
        <ArrowForwardIos color='inherit' classes={{ root: classes.arrow }}/>
        <Button component={Link} to={`/dashboard/catalogs/cities/${cityId}`} variant={location.pathname === `/dashboard/catalogs/cities/${cityId}` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/catalogs/cities/${cityId}` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Overview')}
        </Button>
        <Button component={Link} to={`/dashboard/catalogs/cities/${cityId}/reports`} variant={location.pathname === `/dashboard/catalogs/cities/${cityId}/reports` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/catalogs/cities/${cityId}/reports` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Reports')}
        </Button>
        <Button component={Link} to={`/dashboard/catalogs/cities/${cityId}/knowledge`} variant={location.pathname.includes(`/dashboard/catalogs/cities/${cityId}/knowledge`) ? 'contained' : 'text'} size="small"
                color={location.pathname.includes(`/dashboard/catalogs/cities/${cityId}/knowledge`) ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Knowledge')}
        </Button>
      </div>
    );
  }
}

TopMenuCity.propTypes = {
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
)(TopMenuCity);
