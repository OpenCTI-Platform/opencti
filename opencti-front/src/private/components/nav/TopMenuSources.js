import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
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
        <Button component={Link} to='/dashboard/sources' variant={location.pathname === '/dashboard/sources' ? 'contained' : 'text'} size="small"
                color={location.pathname === '/dashboard/sources' ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('Configuration')}
        </Button>
        <Button component={Link} to='/dashboard/sources/references' variant={location.pathname.includes('/dashboard/sources/references') ? 'contained' : 'text'} size="small"
                color={location.pathname.includes('/dashboard/sources/references') ? 'primary' : 'inherit'} classes={{ root: classes.button }}>
          {t('External references')}
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
