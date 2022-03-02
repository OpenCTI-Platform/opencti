import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIos } from '@mui/icons-material';
import { ServerNetwork } from 'mdi-material-ui';
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

class TopMenuInfrastructure extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { infrastructureId },
      },
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/observations/infrastructures"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <ServerNetwork className={classes.icon} fontSize="small" />
          {t('Infrastructures')}
        </Button>
        <ArrowForwardIos color="primary" classes={{ root: classes.arrow }} />
        <Button
          component={Link}
          to={`/dashboard/observations/infrastructures/${infrastructureId}`}
          variant={
            location.pathname
            === `/dashboard/observations/infrastructures/${infrastructureId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/infrastructures/${infrastructureId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/infrastructures/${infrastructureId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/observations/infrastructures/${infrastructureId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/observations/infrastructures/${infrastructureId}/knowledge`,
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
          to={`/dashboard/observations/infrastructures/${infrastructureId}/analysis`}
          variant={
            location.pathname
            === `/dashboard/observations/infrastructures/${infrastructureId}/analysis`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/infrastructures/${infrastructureId}/analysis`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          {t('Analysis')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/infrastructures/${infrastructureId}/indicators`}
          variant={
            location.pathname.includes(
              `/dashboard/observations/infrastructures/${infrastructureId}/indicators`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/observations/infrastructures/${infrastructureId}/indicators`,
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
            to={`/dashboard/observations/infrastructures/${infrastructureId}/files`}
            variant={
              location.pathname
              === `/dashboard/observations/infrastructures/${infrastructureId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/observations/infrastructures/${infrastructureId}/files`
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
          to={`/dashboard/observations/infrastructures/${infrastructureId}/history`}
          variant={
            location.pathname
            === `/dashboard/observations/infrastructures/${infrastructureId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/infrastructures/${infrastructureId}/history`
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

TopMenuInfrastructure.propTypes = {
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
)(TopMenuInfrastructure);
