import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIos } from '@mui/icons-material';
import { ArchiveOutline } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  buttonHome: {
    marginRight: theme.spacing(2),
    padding: '0 5px 0 5px',
    minHeight: 20,
    textTransform: 'none',
  },
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
  arrow: {
    verticalAlign: 'middle',
    marginRight: 10,
  },
});

class TopMenuArtifact extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { observableId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/observations/artifacts"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <ArchiveOutline className={classes.icon} fontSize="small" />
          {t('Artifacts')}
        </Button>
        <ArrowForwardIos color="primary" classes={{ root: classes.arrow }} />
        <Button
          component={Link}
          to={`/dashboard/observations/artifacts/${observableId}`}
          variant={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/artifacts/${observableId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/observations/artifacts/${observableId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/observations/artifacts/${observableId}/knowledge`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/artifacts/${observableId}/sightings`}
          variant={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}/sightings`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}/sightings`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Sightings')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/artifacts/${observableId}/files`}
          variant={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}/files`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}/files`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Data')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/artifacts/${observableId}/history`}
          variant={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/artifacts/${observableId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuArtifact.propTypes = {
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
)(TopMenuArtifact);
