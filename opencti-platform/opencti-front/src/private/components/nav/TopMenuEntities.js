import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import withStyles from '@mui/styles/withStyles';
import Button from '@mui/material/Button';
import {
  PersonOutlined,
  AccountBalanceOutlined,
  DomainOutlined,
  MapOutlined,
  PlaceOutlined,
  StorageOutlined,
  EventOutlined,
} from '@mui/icons-material';
import { CityVariantOutline } from 'mdi-material-ui';
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

class TopMenuEntities extends Component {
  render() {
    const { t, location, classes } = this.props;
    return (
      <UserContext.Consumer>
        {({ helper }) => (
          <div>
            {!helper.isEntityTypeHidden('Entities')
              && !helper.isEntityTypeHidden('Sector') && (
                <Button
                  component={Link}
                  to="/dashboard/entities/sectors"
                  variant={
                    location.pathname === '/dashboard/entities/sectors'
                      ? 'contained'
                      : 'text'
                  }
                  size="small"
                  color={
                    location.pathname === '/dashboard/entities/sectors'
                      ? 'secondary'
                      : 'primary'
                  }
                  classes={{ root: classes.button }}
                >
                  <DomainOutlined className={classes.icon} fontSize="small" />
                  {t('Sectors')}
                </Button>
            )}
            {!helper.isEntityTypeHidden('Country') && (
              <Button
                component={Link}
                to="/dashboard/entities/countries"
                variant={
                  location.pathname === '/dashboard/entities/countries'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/countries'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <MapOutlined className={classes.icon} fontSize="small" />
                {t('Countries')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('City') && (
              <Button
                component={Link}
                to="/dashboard/entities/cities"
                variant={
                  location.pathname === '/dashboard/entities/cities'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/cities'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <CityVariantOutline className={classes.icon} fontSize="small" />
                {t('Cities')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Position') && (
              <Button
                component={Link}
                to="/dashboard/entities/positions"
                variant={
                  location.pathname === '/dashboard/entities/positions'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/positions'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <PlaceOutlined className={classes.icon} fontSize="small" />
                {t('Positions')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Event') && (
              <Button
                component={Link}
                to="/dashboard/entities/events"
                variant={
                  location.pathname === '/dashboard/entities/events'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/events'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <EventOutlined className={classes.icon} fontSize="small" />
                {t('Events')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Organization') && (
              <Button
                component={Link}
                to="/dashboard/entities/organizations"
                variant={
                  location.pathname === '/dashboard/entities/organizations'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/organizations'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <AccountBalanceOutlined
                  className={classes.icon}
                  fontSize="small"
                />
                {t('Organizations')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('System') && (
              <Button
                component={Link}
                to="/dashboard/entities/systems"
                variant={
                  location.pathname === '/dashboard/entities/systems'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/systems'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <StorageOutlined className={classes.icon} fontSize="small" />
                {t('Systems')}
              </Button>
            )}
            {!helper.isEntityTypeHidden('Individual') && (
              <Button
                component={Link}
                to="/dashboard/entities/individuals"
                variant={
                  location.pathname === '/dashboard/entities/individuals'
                    ? 'contained'
                    : 'text'
                }
                size="small"
                color={
                  location.pathname === '/dashboard/entities/individuals'
                    ? 'secondary'
                    : 'primary'
                }
                classes={{ root: classes.button }}
              >
                <PersonOutlined className={classes.icon} fontSize="small" />
                {t('Individuals')}
              </Button>
            )}
          </div>
        )}
      </UserContext.Consumer>
    );
  }
}

TopMenuEntities.propTypes = {
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
  history: PropTypes.object,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(TopMenuEntities);
