import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import { PublicOutlined } from '@mui/icons-material';
import { DiamondOutline, ChessKnight } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';
import { UserContext } from '../../../utils/Security';

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
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            {!helper.isEntityTypeHidden('Threats')
              && !helper.isEntityTypeHidden('Threat-Actor') && (
                <Button
                  component={Link}
                  to="/dashboard/threats/threat_actors"
                  variant={
                    location.pathname.includes(
                      '/dashboard/threats/threat_actors',
                    )
                      ? 'contained'
                      : 'text'
                  }
                  size="small"
                  color={
                    location.pathname.includes(
                      '/dashboard/threats/threat_actors',
                    )
                      ? 'secondary'
                      : 'primary'
                  }
                  classes={{ root: classes.button }}
                >
                  <PublicOutlined className={classes.icon} fontSize="small" />
                  {t('Threat actors')}
                </Button>
            )}
            {!helper.isEntityTypeHidden('Intrusion-Set') && (
              <Button
                component={Link}
                to="/dashboard/threats/intrusion_sets"
                variant={
                  location.pathname.includes(
                    '/dashboard/threats/intrusion_sets',
                  )
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname.includes(
                    '/dashboard/threats/intrusion_sets',
                  )
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <DiamondOutline className={classes.icon} fontSize="small" />
                {t('Intrusion sets')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Campaign') && (
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
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <ChessKnight className={classes.icon} fontSize="small" />
                {t('Campaigns')}
              </Button>
            )}
          </div>
        )}
      </UserContext.Consumer>
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
