import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { ArrowForwardIosOutlined } from '@mui/icons-material';
import { ShieldSearch } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import Security from '../../../utils/Security';
import {
  KNOWLEDGE_KNGETEXPORT,
  KNOWLEDGE_KNUPLOAD,
} from '../../../utils/hooks/useGranted';

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

class TopMenuIndicator extends Component {
  render() {
    const {
      t,
      location,
      id: indicatorId,
      classes,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/observations/indicators"
          variant="contained"
          size="small"
          color="primary"
          classes={{ root: classes.buttonHome }}
        >
          <ShieldSearch className={classes.icon} fontSize="small" />
          {t('Indicators')}
        </Button>
        <ArrowForwardIosOutlined
          color="primary"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/dashboard/observations/indicators/${indicatorId}`}
          variant={
            location.pathname
            === `/dashboard/observations/indicators/${indicatorId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/indicators/${indicatorId}`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!indicatorId}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/indicators/${indicatorId}/knowledge`}
          variant={
            location.pathname.includes(
              `/dashboard/observations/indicators/${indicatorId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/observations/indicators/${indicatorId}/knowledge`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!indicatorId}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/indicators/${indicatorId}/analyses`}
          variant={
            location.pathname.includes(
              `/dashboard/observations/indicators/${indicatorId}/analyses`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/dashboard/observations/indicators/${indicatorId}/analyses`,
            )
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!indicatorId}
        >
          {t('Analyses')}
        </Button>
        <Button
          component={Link}
          to={`/dashboard/observations/indicators/${indicatorId}/sightings`}
          variant={
            location.pathname
            === `/dashboard/observations/indicators/${indicatorId}/sightings`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/indicators/${indicatorId}/sightings`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!indicatorId}
        >
          {t('Sightings')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/dashboard/observations/indicators/${indicatorId}/files`}
            variant={
              location.pathname
              === `/dashboard/observations/indicators/${indicatorId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/dashboard/observations/indicators/${indicatorId}/files`
                ? 'secondary'
                : 'primary'
            }
            classes={{ root: classes.button }}
            disabled={!indicatorId}
          >
            {t('Data')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/dashboard/observations/indicators/${indicatorId}/history`}
          variant={
            location.pathname
            === `/dashboard/observations/indicators/${indicatorId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/dashboard/observations/indicators/${indicatorId}/history`
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
          disabled={!indicatorId}
        >
          {t('History')}
        </Button>
      </div>
    );
  }
}

TopMenuIndicator.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  id: PropTypes.string,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuIndicator);
