import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import {
  LanguageOutlined,
  WorkOutline,
  DescriptionOutlined,
  FeedbackOutlined,
} from '@mui/icons-material';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  button: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuAnalysis extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/analysis/reports"
          variant={
            location.pathname === '/dashboard/analysis/reports'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/reports'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <DescriptionOutlined className={classes.icon} fontSize="small" />
          {t('Reports')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/notes"
          variant={
            location.pathname === '/dashboard/analysis/notes'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/notes'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <WorkOutline className={classes.icon} fontSize="small" />
          {t('Notes')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/opinions"
          variant={
            location.pathname === '/dashboard/analysis/opinions'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/opinions'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <FeedbackOutlined className={classes.icon} fontSize="small" />
          {t('Opinions')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/analysis/external_references"
          variant={
            location.pathname === '/dashboard/analysis/external_references'
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/analysis/external_references'
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <LanguageOutlined className={classes.icon} fontSize="small" />
          {t('External references')}
        </Button>
      </div>
    );
  }
}

TopMenuAnalysis.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuAnalysis);
