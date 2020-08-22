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
    const { t, location, classes } = this.props;
    return (
      <div>
        <Button
          component={Link}
          to="/dashboard/events/incidents"
          variant={
            location.pathname.includes('/dashboard/events/incidents')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/events/incidents')
              ? 'primary'
              : 'inherit'
          }
          classes={{ root: classes.button }}
        >
          <Fire className={classes.icon} fontSize="small" />
          {t('Incidents')}
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
            className={classes.icon}
            fontSize="small"
          />
          {t('Malwares')}
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
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuThreats);
