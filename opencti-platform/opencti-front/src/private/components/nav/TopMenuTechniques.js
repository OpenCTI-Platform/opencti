import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { BugReportOutlined } from '@material-ui/icons';
import { LockPattern, Application, ProgressWrench } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuTechniques extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/techniques/attack_patterns"
          variant={
            location.pathname === '/dashboard/techniques/attack_patterns'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/attack_patterns'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <LockPattern className={classes.icon} fontSize="small" />
          {t('Attack patterns')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/techniques/courses_of_action"
          variant={
            location.pathname === '/dashboard/techniques/courses_of_action'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/courses_of_action'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <ProgressWrench className={classes.icon} fontSize="small" />
          {t('Courses of action')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/techniques/tools"
          variant={
            location.pathname === '/dashboard/techniques/tools'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/tools'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <Application className={classes.icon} fontSize="small" />
          {t('Tools')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/techniques/vulnerabilities"
          variant={
            location.pathname === '/dashboard/techniques/vulnerabilities'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/techniques/vulnerabilities'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <BugReportOutlined className={classes.icon} fontSize="small" />
          {t('Vulnerabilities')}
        </Button>
      </div>
    );
  }
}

TopMenuTechniques.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuTechniques);
