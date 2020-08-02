import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIosOutlined } from '@material-ui/icons';
import { Fire } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/Security';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '2px 5px 2px 5px',
    minHeight: 20,
    textTransform: 'none',
    color: '#666666',
    backgroundColor: '#ffffff',
  },
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
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuXOpenCTIIncident extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { XOpenCTIIncidentId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/threats/XOpenCTIIncidents"
          variant="contained"
          size="small"
          color="inherit"
          classes={{ root: classes.buttonHome }}
        >
          <Fire className={classes.icon} fontSize="small" />
          {t('Incidents')}
        </Button>
        <ArrowForwardIosOutlined
          color="inherit"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}`}
          variant={
            location.pathname
            === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/knowledge`,
            )
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/reports`}
          variant={
            location.pathname
            === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/reports`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/reports`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Reports')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/observables`}
          variant={
            location.pathname.includes(
              `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/observables`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/observables`,
            )
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Observables')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/files`}
            variant={
              location.pathname
              === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/files`
                ? 'primary'
                : 'inherit'
            }
            classes={{ root: classes.button }}
          >
            {t('Files')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/history`}
          variant={
            location.pathname
            === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/XOpenCTIIncidents/${XOpenCTIIncidentId}/history`
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuXOpenCTIIncident.propTypes = {
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
)(TopMenuXOpenCTIIncident);
