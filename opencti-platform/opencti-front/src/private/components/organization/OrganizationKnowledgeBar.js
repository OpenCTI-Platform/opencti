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
import { Domain, Person, Map } from '@material-ui/icons';
import { Gauge, TargetVariant } from 'mdi-material-ui';
import inject18n from '../../../components/i18n';

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

class OrganizationKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, organizationId,
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
            to={`/dashboard/entities/organizations/${organizationId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/entities/organizations/${organizationId}/knowledge/overview`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Gauge />
            </ListItemIcon>
            <ListItemText primary={t('Overview')} secondary={t('Statistics')} />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/organizations/${organizationId}/knowledge/sectors`}
            selected={
              location.pathname
              === `/dashboard/entities/organizations/${organizationId}/knowledge/sectors`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Domain />
            </ListItemIcon>
            <ListItemText
              primary={t('Sectors')}
              secondary={t('Related to this organization')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/organizations/${organizationId}/knowledge/locations`}
            selected={
              location.pathname
              === `/dashboard/entities/organizations/${organizationId}/knowledge/locations`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Map />
            </ListItemIcon>
            <ListItemText
              primary={t('Localization')}
              secondary={t('Locations of this organization')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/organizations/${organizationId}/knowledge/persons`}
            selected={
              location.pathname
              === `/dashboard/entities/organizations/${organizationId}/knowledge/persons`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Person />
            </ListItemIcon>
            <ListItemText
              primary={t('Persons')}
              secondary={t('Belonging to this organization')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/organizations/${organizationId}/knowledge/threats`}
            selected={
              location.pathname
              === `/dashboard/entities/organizations/${organizationId}/knowledge/threats`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <TargetVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Targeting this organization')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

OrganizationKnowledgeBar.propTypes = {
  organizationId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(OrganizationKnowledgeBar);
