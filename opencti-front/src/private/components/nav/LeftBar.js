import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { withStyles } from '@material-ui/core/styles';
import ClickAwayListener from '@material-ui/core/ClickAwayListener';
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
} from '@material-ui/icons';
import {
  Settings, ClipboardArrowDown, Database,
} from 'mdi-material-ui';
import { compose, includes, propOr } from 'ramda';
import { createFragmentContainer } from 'react-relay';
import graphql from 'babel-plugin-relay/macro';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    position: 'fixed',
    width: 60,
    backgroundColor: theme.palette.background.nav,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  drawerPaperOpen: {
    minHeight: '100vh',
    position: 'fixed',
    width: 220,
    backgroundColor: theme.palette.background.nav,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  menuList: {
    height: '100%',
  },
  lastItem: {
    bottom: 0,
  },
  logoContainer: {
    margin: '6px 20px 0px -5px',
  },
  logo: {
    cursor: 'pointer',
    width: 35,
  },
  toolbar: theme.mixins.toolbar,
});

class LeftBar extends Component {
  constructor(props) {
    super(props);
    this.state = { open: false };
  }

  toggle() {
    this.setState({ open: !this.state.open });
  }

  handleClickAway() {
    if (this.state.open) {
      this.toggle();
    }
  }

  render() {
    const {
      t, location, classes, me,
    } = this.props;
    return (
      <ClickAwayListener onClickAway={this.handleClickAway.bind(this)}>
        <Drawer
          variant="permanent"
          open={this.state.open}
          classes={{
            paper: this.state.open
              ? classes.drawerPaperOpen
              : classes.drawerPaper,
          }}
        >
          <div className={classes.toolbar} />
          <MenuList component="nav">
            <MenuItem
              component={Link}
              to="/dashboard"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname === '/dashboard'}
              dense={false}
            >
              <ListItemIcon>
                <Dashboard />
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Dashboard')} /> : ''}
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/knowledge"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/knowledge')}
              dense={false}
            >
              <ListItemIcon>
                <Database />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Knowledge')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/observables"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/observables')}
              dense={false}
            >
              <ListItemIcon>
                <Layers />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Observables')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/reports"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/reports')}
              dense={false}
            >
              <ListItemIcon>
                <Assignment />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Reports')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/catalogs"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/catalogs')}
              dense={false}
            >
              <ListItemIcon>
                <ListAlt />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Catalogs')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
          </MenuList>
          <Divider />
          <MenuList component="nav">
            <MenuItem
              component={Link}
              to="/dashboard/explore"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/explore')}
              dense={false}
            >
              <ListItemIcon>
                <Explore />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Explore')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/investigate"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/investigate')}
              dense={false}
            >
              <ListItemIcon>
                <DeviceHub />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Investigate')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/correlate"
              onClick={this.handleClickAway.bind(this)}
              selected={location.pathname.includes('/dashboard/correlate')}
              dense={false}
            >
              <ListItemIcon>
                <GroupWork />
              </ListItemIcon>
              {this.state.open ? (
                <ListItemText
                  primary={t('Correlate')}
                  classes={{ root: classes.listText }}
                />
              ) : (
                ''
              )}
            </MenuItem>
          </MenuList>
          {includes('ROLE_ADMIN', propOr([], 'grant', me)) && (
            <div>
              <Divider />
              <MenuList component="nav">
                <MenuItem
                  component={Link}
                  to="/dashboard/sources"
                  onClick={this.handleClickAway.bind(this)}
                  selected={location.pathname.includes('/dashboard/sources')}
                  dense={false}
                >
                  <ListItemIcon>
                    <ClipboardArrowDown />
                  </ListItemIcon>
                  {this.state.open ? (
                    <ListItemText
                      primary={t('Sources')}
                      classes={{ root: classes.listText }}
                    />
                  ) : (
                    ''
                  )}
                </MenuItem>
                <MenuItem
                  component={Link}
                  to="/dashboard/settings"
                  onClick={this.handleClickAway.bind(this)}
                  selected={location.pathname.includes('/dashboard/settings')}
                  dense={false}
                >
                  <ListItemIcon>
                    <Settings />
                  </ListItemIcon>
                  {this.state.open ? (
                    <ListItemText
                      primary={t('Settings')}
                      classes={{ root: classes.listText }}
                    />
                  ) : (
                    ''
                  )}
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
                {this.state.open ? (
                  <KeyboardArrowLeft />
                ) : (
                  <KeyboardArrowRight />
                )}
              </ListItemIcon>
            </MenuItem>
          </MenuList>
        </Drawer>
      </ClickAwayListener>
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
