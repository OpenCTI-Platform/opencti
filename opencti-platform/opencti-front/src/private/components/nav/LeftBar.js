import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import Toolbar from '@material-ui/core/Toolbar';
import IconButton from '@material-ui/core/IconButton';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Divider from '@material-ui/core/Divider';
import Drawer from '@material-ui/core/Drawer';
import {
  Dashboard,
  Explore,
  Assignment,
  DeviceHub,
  KeyboardArrowLeft,
  KeyboardArrowRight,
  Layers,
  ListAlt,
  GroupWork,
  Extension,
} from '@material-ui/icons';
import { Settings, Database, Binoculars } from 'mdi-material-ui';
import { compose, includes, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import logo from '../../../resources/images/logo_text.png';
import inject18n from '../../../components/i18n';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 60,
    backgroundColor: theme.palette.background.nav,
  },
  drawerPaperOpen: {
    minHeight: '100vh',
    width: 220,
    backgroundColor: theme.palette.background.nav,
  },
  menuList: {
    height: '100%',
  },
  lastItem: {
    bottom: 0,
  },
  logoButton: {
    marginLeft: -23,
    marginRight: 20,
  },
  logo: {
    cursor: 'pointer',
    height: 35,
  },
  toolbar: theme.mixins.toolbar,
  menuItem: {
    height: 40,
  },
});

class LeftBar extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  toggle() {
    this.setState({ open: !this.state.open });
  }

  render() {
    const {
      t, location, classes, me,
    } = this.props;
    return (
      <div>
        <Drawer variant="permanent" classes={{ paper: classes.drawerPaper }}>
          <div className={classes.toolbar} />
          <MenuList component="nav">
            <MenuItem
              component={Link}
              to="/dashboard"
              selected={location.pathname === '/dashboard'}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Dashboard />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/threats"
              selected={location.pathname.includes('/dashboard/threats')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Database />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/techniques"
              selected={location.pathname.includes('/dashboard/techniques')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Layers />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/observables"
              selected={location.pathname.includes('/dashboard/observables')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Binoculars />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/reports"
              selected={location.pathname.includes('/dashboard/reports')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Assignment />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/entities"
              selected={location.pathname.includes('/dashboard/entities')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <ListAlt />
              </ListItemIcon>
            </MenuItem>
          </MenuList>
          <Divider />
          <MenuList component="nav">
            <MenuItem
              component={Link}
              to="/dashboard/explore"
              selected={location.pathname.includes('/dashboard/explore')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Explore />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              disabled={true}
              to="/dashboard/investigate"
              selected={location.pathname.includes('/dashboard/investigate')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <DeviceHub />
              </ListItemIcon>
            </MenuItem>
            <MenuItem
              component={Link}
              disabled={true}
              to="/dashboard/correlate"
              selected={location.pathname.includes('/dashboard/correlate')}
              dense={false}
            >
              <ListItemIcon>
                <GroupWork />
              </ListItemIcon>
            </MenuItem>
          </MenuList>
          {includes('ROLE_ADMIN', propOr([], 'grant', me)) && (
            <div>
              <Divider />
              <MenuList component="nav">
                <MenuItem
                  component={Link}
                  to="/dashboard/connectors"
                  selected={location.pathname.includes('/dashboard/connectors')}
                  dense={false}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon>
                    <Extension />
                  </ListItemIcon>
                </MenuItem>
                <MenuItem
                  component={Link}
                  to="/dashboard/settings"
                  selected={location.pathname.includes('/dashboard/settings')}
                  dense={false}
                  style={{ marginBottom: 50 }}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon>
                    <Settings />
                  </ListItemIcon>
                </MenuItem>
              </MenuList>
            </div>
          )}
          <MenuList
            component="nav"
            classes={{ root: this.props.classes.menuList }}
          >
            <MenuItem
              onClick={this.toggle.bind(this)}
              dense={false}
              style={{ position: 'absolute', bottom: 10, width: '100%' }}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <KeyboardArrowRight />
              </ListItemIcon>
            </MenuItem>
          </MenuList>
        </Drawer>
        <Drawer
          open={this.state.open}
          classes={{ paper: classes.drawerPaperOpen }}
          onClose={this.toggle.bind(this)}
        >
          <Toolbar>
            <IconButton
              classes={{ root: classes.logoButton }}
              color="inherit"
              aria-label="Menu"
              component={Link}
              to="/dashboard"
            >
              <img src={logo} alt="logo" className={classes.logo} />
            </IconButton>
          </Toolbar>
          <MenuList component="nav">
            <MenuItem
              component={Link}
              to="/dashboard"
              onClick={this.toggle.bind(this)}
              selected={location.pathname === '/dashboard'}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Dashboard />
              </ListItemIcon>
              <ListItemText primary={t('Dashboard')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/threats"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/threats')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Database />
              </ListItemIcon>
              <ListItemText primary={t('Threats')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/techniques"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/techniques')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Layers />
              </ListItemIcon>
              <ListItemText primary={t('Techniques')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/observables"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/observables')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Binoculars />
              </ListItemIcon>
              <ListItemText primary={t('Observables')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/reports"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/reports')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Assignment />
              </ListItemIcon>
              <ListItemText primary={t('Reports')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/entities"
              selected={location.pathname.includes('/dashboard/entities')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <ListAlt />
              </ListItemIcon>
              <ListItemText primary={t('Entities')} />
            </MenuItem>
          </MenuList>
          <Divider />
          <MenuList component="nav">
            <MenuItem
              component={Link}
              to="/dashboard/explore"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/explore')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <Explore />
              </ListItemIcon>
              <ListItemText primary={t('Explore')} />
            </MenuItem>
            <MenuItem
              component={Link}
              disabled={true}
              to="/dashboard/investigate"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/investigate')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <DeviceHub />
              </ListItemIcon>
              <ListItemText primary={t('Investigate')} />
            </MenuItem>
            <MenuItem
              component={Link}
              disabled={true}
              to="/dashboard/correlate"
              onClick={this.toggle.bind(this)}
              selected={location.pathname.includes('/dashboard/correlate')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon>
                <GroupWork />
              </ListItemIcon>
              <ListItemText primary={t('Correlate')} />
            </MenuItem>
          </MenuList>
          {includes('ROLE_ADMIN', propOr([], 'grant', me)) && (
            <div>
              <Divider />
              <MenuList component="nav">
                <MenuItem
                  component={Link}
                  to="/dashboard/connectors"
                  onClick={this.toggle.bind(this)}
                  selected={location.pathname.includes('/dashboard/connectors')}
                  dense={false}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon>
                    <Extension />
                  </ListItemIcon>
                  <ListItemText primary={t('Connectors')} />
                </MenuItem>
                <MenuItem
                  component={Link}
                  to="/dashboard/settings"
                  onClick={this.toggle.bind(this)}
                  selected={location.pathname.includes('/dashboard/settings')}
                  dense={false}
                  classes={{ root: classes.menuItem }}
                  style={{ marginBottom: 50 }}
                >
                  <ListItemIcon>
                    <Settings />
                  </ListItemIcon>
                  <ListItemText primary={t('Settings')} />
                </MenuItem>
              </MenuList>
            </div>
          )}
          <MenuList
            component="nav"
            classes={{ root: this.props.classes.menuList }}
          >
            <MenuItem
              onClick={this.toggle.bind(this)}
              dense={false}
              style={{ position: 'absolute', bottom: 10, width: '100%' }}
            >
              <ListItemIcon>
                <KeyboardArrowLeft />
              </ListItemIcon>
            </MenuItem>
          </MenuList>
        </Drawer>
      </div>
    );
  }
}

LeftBar.propTypes = {
  me: PropTypes.object,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

const LeftBarFragment = createFragmentContainer(LeftBar, {
  me: graphql`
    fragment LeftBar_me on User {
      grant
    }
  `,
});

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(LeftBarFragment);
