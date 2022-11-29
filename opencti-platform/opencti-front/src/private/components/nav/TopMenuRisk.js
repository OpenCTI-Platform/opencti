import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ShieldPlus, TextSearch } from 'mdi-material-ui';
import NoteRoundedIcon from '@material-ui/icons/NoteRounded';
import ChevronRightIcon from '@material-ui/icons/ChevronRight';
import HistoryIcon from '@material-ui/icons/History';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '4px 5px',
    minHeight: 20,
    textTransform: 'none',
  },
  button: {
    marginRight: theme.spacing(1),
    padding: '4px 25px',
    minHeight: 20,
    minWidth: 20,
    textTransform: 'none',
    color: '#fff',
  },
  icon: {
    marginRight: theme.spacing(1),
  },
});

class TopMenuRisk extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { riskId },
      },
      classes,
    } = this.props;
    return (
      <div className={classes.root}>
        <Button
          component={Link}
          to='/activities/risk_assessment/risks'
          variant="contained"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          {t('Risks')}
        </Button>
        <ChevronRightIcon
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/activities/risk_assessment/risks/${riskId}`}
          variant={
            location.pathname
              === `/activities/risk_assessment/risks/${riskId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
              === `/activities/risk_assessment/risks/${riskId}`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <NoteRoundedIcon className={classes.icon} />
          {t('OVERVIEW')}
        </Button>
        {/* <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}> */}
        <Button
          component={Link}
          to={`/activities/risk_assessment/risks/${riskId}/analysis`}
          variant={
            location.pathname
              === `/activities/risk_assessment/risks/${riskId}/analysis`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
              === `/activities/risk_assessment/risks/${riskId}/analysis`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {/* <ManageSearchIcon className={classes.icon} /> */}
          <TextSearch className={classes.icon} />
          {t('ANALYSIS')}
        </Button>
        {/* </Security> */}
        <Button
          component={Link}
          to={`/activities/risk_assessment/risks/${riskId}/remediation`}
          variant={
            location.pathname.includes(`/activities/risk_assessment/risks/${riskId}/remediation`)
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(`/activities/risk_assessment/risks/${riskId}/remediation`)
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {/* <AddModeratorIcon className={classes.icon} /> */}
          <ShieldPlus className={classes.icon} />
          {t('REMEDIATION')}
        </Button>
        <Button
          component={Link}
          to={`/activities/risk_assessment/risks/${riskId}/tracking`}
          variant={
            location.pathname.includes(
              `/activities/risk_assessment/risks/${riskId}/tracking`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/activities/risk_assessment/risks/${riskId}/tracking`,
            )
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <HistoryIcon className={classes.icon} />
          {t('TRACKING')}
        </Button>
      </div>
    );
  }
}

TopMenuRisk.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  breadcrumbs: PropTypes.bool,
  match: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuRisk);
