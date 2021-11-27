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
    marginRight: theme.spacing(1),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
});

class TopMenuDashboard extends Component {
  render() {
    const {
      t,
      location,
      classes,
      handleChangeTimeField,
      timeField,
      handleChangeDashboard,
      dashboard,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard"
          variant={location.pathname === '/dashboard' ? 'contained' : 'text'}
          size="small"
          color={location.pathname === '/dashboard' ? 'secondary' : 'inherit'}
          classes={{ root: classes.button }}
        >
          {t('Dashboard')}
        </Button>
        <DashboardSettings
          handleChangeTimeField={handleChangeTimeField}
          timeField={timeField}
          handleChangeDashboard={handleChangeDashboard}
          dashboard={dashboard}
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
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuDashboard);
