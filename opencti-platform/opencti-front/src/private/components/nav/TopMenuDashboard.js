import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import inject18n from '../../../components/i18n';
import DashboardSettings from '../DashboardSettings';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '4px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
});

class TopMenuDashboard extends Component {
  render() {
    const {
      t, location, classes, dashboard, handleChangeDashboard,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard"
          variant={location.pathname === '/dashboard' ? 'contained' : 'text'}
          size="small"
          color={location.pathname === '/dashboard' ? 'primary' : 'inherit'}
          classes={{ root: classes.button }}
        >
          {t('Dashboard')}
        </Button>
        <DashboardSettings
          dashboard={dashboard}
          handleChangeDashboard={handleChangeDashboard}
          isDashboard={true}
        />
      </div>
    );
  }
}

TopMenuDashboard.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  dashboard: PropTypes.string,
  handleChangeDashboard: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuDashboard);
