import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import windowDimensions from 'react-window-dimensions';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Button from '@material-ui/core/Button';
import { PublicOutlined } from '@material-ui/icons';
import {
  Biohazard, DiamondOutline, Fire, ChessKnight,
} from 'mdi-material-ui';
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

class TopMenuThreats extends Component {
  render() {
    const {
      t, location, classes, width,
    } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/threats/threat_actors"
          variant={
            location.pathname.includes('/dashboard/threats/threat_actors')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/threats/threat_actors')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <PublicOutlined
            className={width > 950 ? classes.icon : ''}
            fontSize="small"
          />
          {width > 950 ? t('Threat actors') : ''}
        </Button>
        <Button
          component={Link}
          to="/dashboard/threats/intrusion_sets"
          variant={
            location.pathname.includes('/dashboard/threats/intrusion_sets')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/threats/intrusion_sets')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <DiamondOutline
            className={width > 950 ? classes.icon : ''}
            fontSize="small"
          />
          {width > 950 ? t('Intrusion sets') : ''}
        </Button>
        <Button
          component={Link}
          to="/dashboard/threats/campaigns"
          variant={
            location.pathname.includes('/dashboard/threats/campaigns')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname === '/dashboard/threats/campaigns'
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <ChessKnight
            className={width > 950 ? classes.icon : ''}
            fontSize="small"
          />
          {width > 950 ? t('Campaigns') : ''}
        </Button>
        <Button
          component={Link}
          to="/dashboard/threats/incidents"
          variant={
            location.pathname.includes('/dashboard/threats/incidents')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/threats/incidents')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <Fire className={width > 950 ? classes.icon : ''} fontSize="small" />
          {width > 950 ? t('Incidents') : ''}
        </Button>
        <Button
          component={Link}
          to="/dashboard/threats/malwares"
          variant={
            location.pathname.includes('/dashboard/threats/malwares')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/threats/malwares')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <Biohazard
            className={width > 950 ? classes.icon : ''}
            fontSize="small"
          />
          {width > 950 ? t('Malwares') : ''}
        </Button>
      </div>
    );
  }
}

TopMenuThreats.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
  width: PropTypes.number,
};

export default compose(
  inject18n,
  withRouter,
  windowDimensions(),
  withStyles(styles),
)(TopMenuThreats);
