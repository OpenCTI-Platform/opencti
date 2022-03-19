import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { WifiTetheringOutlined, VisibilityOutlined } from '@mui/icons-material';
import { Fire } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
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
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <Fire className={classes.icon} fontSize="small" />
          {t('Incidents')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/events/sightings"
          variant={
            location.pathname.includes('/dashboard/events/sightings')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/events/sightings')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <VisibilityOutlined className={classes.icon} fontSize="small" />
          {t('Sightings')}
        </Button>
        <Button
          component={Link}
          to="/dashboard/events/observed_data"
          variant={
            location.pathname.includes('/dashboard/events/observed_data')
              ? 'contained'
              : 'text'
          }
          size="small"
          color={
            location.pathname.includes('/dashboard/events/observed_data')
              ? 'secondary'
              : 'primary'
          }
          classes={{ root: classes.button }}
        >
          <WifiTetheringOutlined className={classes.icon} fontSize="small" />
          {t('Observed datas')}
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
