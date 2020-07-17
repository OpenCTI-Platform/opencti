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
import { AccountBalance, Map } from '@material-ui/icons';
import { Gauge, SourcePull, TargetVariant } from 'mdi-material-ui';
import inject18n from '../../../../components/i18n';

const styles = (theme) => ({
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

class IndividualKnowledgeBar extends Component {
  render() {
    const {
      t, location, classes, individualId,
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
            to={`/dashboard/entities/individuals/${individualId}/knowledge/overview`}
            selected={
              location.pathname
              === `/dashboard/entities/individuals/${individualId}/knowledge/overview`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Gauge />
            </ListItemIcon>
            <ListItemText
              primary={t('Overview')}
              secondary={t('Synthesis of knowledge')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/individuals/${individualId}/knowledge/organizations`}
            selected={
              location.pathname
              === `/dashboard/entities/individuals/${individualId}/knowledge/organizations`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <AccountBalance />
            </ListItemIcon>
            <ListItemText
              primary={t('Organizations')}
              secondary={t('This individual is part of')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/individuals/${individualId}/knowledge/locations`}
            selected={
              location.pathname
              === `/dashboard/entities/individuals/${individualId}/knowledge/locations`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <Map />
            </ListItemIcon>
            <ListItemText
              primary={t('Locations')}
              secondary={t('Locations of this individual')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/individuals/${individualId}/knowledge/threats`}
            selected={
              location.pathname
              === `/dashboard/entities/individuals/${individualId}/knowledge/threats`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <TargetVariant />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Targeting this individual')}
            />
          </MenuItem>
          <MenuItem
            component={Link}
            to={`/dashboard/entities/individuals/${individualId}/knowledge/attribution`}
            selected={
              location.pathname
              === `/dashboard/entities/individuals/${individualId}/knowledge/attribution`
            }
            dense={false}
            classes={{ root: classes.item }}
          >
            <ListItemIcon>
              <SourcePull />
            </ListItemIcon>
            <ListItemText
              primary={t('Threats')}
              secondary={t('Attributed to this individual')}
            />
          </MenuItem>
        </MenuList>
      </Drawer>
    );
  }
}

IndividualKnowledgeBar.propTypes = {
  individualId: PropTypes.string,
  classes: PropTypes.object,
  location: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(IndividualKnowledgeBar);
