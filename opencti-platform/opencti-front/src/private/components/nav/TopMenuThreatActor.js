import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined, PublicOutlined } from '@mui/icons-material';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/Security';

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

class TopMenuThreatActor extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { threatActorId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/threats/threat_actors"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <PublicOutlined className={classes.icon} fontSize="small" />
          {t('Threat actors')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors/${threatActorId}`}
          variant={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors/${threatActorId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/threats/threat_actors/${threatActorId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/threats/threat_actors/${threatActorId}/knowledge`,
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
          to={`/dashboard/threats/threat_actors/${threatActorId}/analysis`}
          variant={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}/analysis`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}/analysis`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Analysis')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors/${threatActorId}/indicators`}
          variant={
            location.pathname.includes(
              `/dashboard/threats/threat_actors/${threatActorId}/indicators`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/threats/threat_actors/${threatActorId}/indicators`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Indicators')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/threats/threat_actors/${threatActorId}/files`}
            variant={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/threats/threat_actors/${threatActorId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/threats/threat_actors/${threatActorId}/history`}
          variant={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/threats/threat_actors/${threatActorId}/history`
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

TopMenuThreatActor.propTypes = {
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
)(TopMenuThreatActor);
