import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIos, Description } from '@material-ui/icons';
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

class TopMenuReport extends Component {
  render() {
    const {
      t, location, match: { params: { reportId } }, classes,
    } = this.props;
    return (
      <div>
        <Button component={Link} to='/dashboard/reports/all' variant='contained' size="small"
                color='inherit' classes={{ root: classes.buttonHome }}>
          <Description className={classes.icon} fontSize='small'/>
          {t('Reports')}
        </Button>
        <ArrowForwardIos color='inherit' classes={{ root: classes.arrow }}/>
        <Button component={Link} to={`/dashboard/reports/all/${reportId}`} variant={location.pathname === `/dashboard/reports/all/${reportId}` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/reports/all/${reportId}` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Overview')}
        </Button>
        <Button component={Link} to={`/dashboard/reports/all/${reportId}/knowledge`} variant={location.pathname === `/dashboard/reports/all/${reportId}/knowledge` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/reports/all/${reportId}/knowledge` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Knowledge')}
        </Button>
        <Button component={Link} to={`/dashboard/reports/all/${reportId}/observables`} variant={location.pathname === `/dashboard/reports/all/${reportId}/observables` ? 'contained' : 'text'} size="small"
                color={location.pathname === `/dashboard/reports/all/${reportId}/observables` ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Observables')}
        </Button>
      </div>
    );
  }
}

TopMenuReport.propTypes = {
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
)(TopMenuReport);
