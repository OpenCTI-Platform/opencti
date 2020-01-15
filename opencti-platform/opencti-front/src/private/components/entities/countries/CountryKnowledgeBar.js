import React, { Component } from 'react';
import PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Drawer from '@material-ui/core/Drawer';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import { AccountBalance } from '@material-ui/icons';
import { Gauge, TargetVariant, CityVariant } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

const styles = theme => ({
  drawer: {
    minHeight: '100vh',
    width: 260,
    position: 'fixed',
    overflow: 'auto',
    padding: 0,
    backgroundColor: theme.palette.background.navLight,
  },
  item: {
    padding: '0 0 0 15px',
  },
  toolbar: theme.mixins.toolbar,
});

class CountryKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, countryId,
    } = this.props;
    return (
      <Drawer
        variant="permanent"
        anchor="right"
        classes={{ paper: classes.drawer }}
      >
        <div className={classes.toolbar} />
        <MenuList component="nav">
          <MenuItem
            component={Link}
            to={`/dashboard/entities/countries/${countryId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/entities/countries/${countryId}/knowledge/overview`
            }
            dense={false}
            classes={{ root: classes.item }}
          >

            <ListItemIcon>
              <Gauge />
            </ListItemIcon>
            <ListItemText primary={t('Overview')} secondary={t('Synthesis of knowledge')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/countries/${countryId}/knowledge/cities`}
            selected={
              location.pathname
              === `/dashboard/entities/countries/${countryId}/knowledge/cities`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <CityVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Cities')}
              secondary={t('Localized in this country')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/countries/${countryId}/knowledge/organizations`}
            selected={
              location.pathname
              === `/dashboard/entities/countries/${countryId}/knowledge/organizations`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <AccountBalance />
            </ListItemIcon>
            <ListItemText
              primary={t('Organizations')}
              secondary={t('Localized in this country')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/countries/${countryId}/knowledge/threats`}
            selected={
              location.pathname
              === `/dashboard/entities/countries/${countryId}/knowledge/threats`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <TargetVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Targeting this country')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

CountryKnowledgeBar.propTypes = {
  countryId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(CountryKnowledgeBar);
