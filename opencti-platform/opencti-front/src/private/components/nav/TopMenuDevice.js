/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Link, withRouter } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIosOutlined, PublicOutlined } from '@material-ui/icons';
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

class TopMenuDevice extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { deviceId },
      },
      classes,
    } = this.props;
    return (
      <div>
        {/* {!deviceId && (
          <Button
            component={Link}
            to="/defender_hq/assets/devices"
            variant="contained"
            size="small"
            color="inherit"
            classes={{ root: classes.buttonHome }}
          >
            <PublicOutlined className={classes.icon} fontSize="small" />
            {t('Device')}
          </Button>
        )} */}
        {/* <ArrowForwardIosOutlined
          color="inherit"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/defender_hq/assets/devices/${deviceId}`}
          variant={
            location.pathname
            === `/defender_hq/assets/devices/${deviceId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/defender_hq/assets/devices/${deviceId}`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/defender_hq/assets/devices/${deviceId}/knowledge`}
          variant={
            location.pathname.includes(
              `/defender_hq/assets/devices/${deviceId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/defender_hq/assets/devices/${deviceId}/knowledge`,
            )
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Knowledge')}
        </Button>
        <Button
          component={Link}
          to={`/defender_hq/assets/devices/${deviceId}/analysis`}
          variant={
            location.pathname
            === `/defender_hq/assets/devices/${deviceId}/analysis`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/defender_hq/assets/devices/${deviceId}/analysis`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Analysis')}
        </Button>
        <Button
          component={Link}
          to={`/defender_hq/assets/devices/${deviceId}/indicators`}
          variant={
            location.pathname.includes(
              `/defender_hq/assets/devices/${deviceId}/indicators`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/defender_hq/assets/devices/${deviceId}/indicators`,
            )
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Indicators')}
        </Button>
        <Security needs={[KNOWLEDGE_KNUPLOAD, KNOWLEDGE_KNGETEXPORT]}>
          <Button
            component={Link}
            to={`/defender_hq/assets/devices/${deviceId}/files`}
            variant={
              location.pathname
              === `/defender_hq/assets/devices/${deviceId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/defender_hq/assets/devices/${deviceId}/files`
                ? 'secondary'
                : 'inherit'
            }
            classes={{ root: classes.button }}
          >
            {t('Files')}
          </Button>
        </Security>
        <Button
          component={Link}
          to={`/defender_hq/assets/devices/${deviceId}/history`}
          variant={
            location.pathname
            === `/defender_hq/assets/devices/${deviceId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/defender_hq/assets/devices/${deviceId}/history`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('History')}
        </Button> */}
      </div>
    );
  }
}

TopMenuDevice.propTypes = {
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
)(TopMenuDevice);
