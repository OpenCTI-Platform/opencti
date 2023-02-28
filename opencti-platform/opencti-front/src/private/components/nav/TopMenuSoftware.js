/* eslint-disable */
/* refactor */
import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { ArrowForwardIosOutlined } from '@material-ui/icons';
import { ChessKnight } from 'mdi-material-ui';
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

class TopMenuSoftware extends Component {
  render() {
    const {
      t,
      location,
      match: {
        params: { softwareId },
      },
      classes,
    } = this.props;
    return (
      <div>
        {/* {!softwareId && (
          <Button
            component={Link}
            to="/defender_hq/assets/software"
            variant="contained"
            size="small"
            color="inherit"
            classes={{ root: classes.buttonHome }}
          >
            <ChessKnight className={classes.icon} fontSize="small" />
            {t('Software')}
          </Button>
        )} */}
        {/* <ArrowForwardIosOutlined
          color="inherit"
          classes={{ root: classes.arrow }}
        />
        <Button
          component={Link}
          to={`/defender_hq/assets/software/${softwareId}`}
          variant={
            location.pathname === `/defender_hq/assets/software/${softwareId}`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === `/defender_hq/assets/software/${softwareId}`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Overview')}
        </Button>
        <Button
          component={Link}
          to={`/defender_hq/assets/software/${softwareId}/knowledge`}
          variant={
            location.pathname.includes(
              `/defender_hq/assets/software/${softwareId}/knowledge`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/defender_hq/assets/software/${softwareId}/knowledge`,
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
          to={`/defender_hq/assets/software/${softwareId}/analysis`}
          variant={
            location.pathname
            === `/defender_hq/assets/software/${softwareId}/analysis`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/defender_hq/assets/software/${softwareId}/analysis`
              ? 'secondary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          {t('Analysis')}
        </Button>
        <Button
          component={Link}
          to={`/defender_hq/assets/software/${softwareId}/indicators`}
          variant={
            location.pathname.includes(
              `/defender_hq/assets/software/${softwareId}/indicators`,
            )
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes(
              `/defender_hq/assets/software/${softwareId}/indicators`,
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
            to={`/defender_hq/assets/software/${softwareId}/files`}
            variant={
              location.pathname
              === `/defender_hq/assets/software/${softwareId}/files`
                ? 'contained'
                : 'text'
            }
            size="small"
            color={
              location.pathname
              === `/defender_hq/assets/software/${softwareId}/files`
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
          to={`/defender_hq/assets/software/${softwareId}/history`}
          variant={
            location.pathname
            === `/defender_hq/assets/software/${softwareId}/history`
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname
            === `/defender_hq/assets/software/${softwareId}/history`
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

TopMenuSoftware.propTypes = {
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
)(TopMenuSoftware);
