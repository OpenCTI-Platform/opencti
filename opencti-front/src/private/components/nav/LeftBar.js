import React, { Component } from 'react';
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
  Explore, Assignment, DeviceHub, KeyboardArrowLeft, KeyboardArrowRight, Layers
} from '@material-ui/icons';
import {
  Settings, ClipboardArrowDown, Gauge, Database,
} from 'mdi-material-ui';
import * as PropTypes from 'prop-types';
import { compose } from 'ramda';
import inject18n from '../../../components/i18n';

const styles = theme => ({
  drawerPaper: {
    minHeight: '100vh',
    position: 'fixed',
    width: 60,
    overflow: 'hidden',
    backgroundColor: theme.palette.nav.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  drawerPaperOpen: {
    minHeight: '100vh',
    position: 'fixed',
    width: 220,
    overflow: 'hidden',
    backgroundColor: theme.palette.nav.background,
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  menuList: {
    height: '100%',
  },
  listIcon: {
    marginRight: 5,
  },
  listText: {
    paddingRight: 5,
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
    const { t, location, classes } = this.props;
    return (
      <ClickAwayListener onClickAway={this.handleClickAway.bind(this)}>
        <Drawer
          variant='permanent'
          open={this.state.open}
          classes={{ paper: this.state.open ? classes.drawerPaperOpen : classes.drawerPaper }}
        >
          <div className={classes.toolbar}/>
          <MenuList component='nav' classes={{ root: classes.menuList }}>
            <MenuItem component={Link} to='/dashboard' onClick={this.handleClickAway.bind(this)} selected={location.pathname === '/dashboard'} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <Gauge/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Dashboard')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/knowledge' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/knowledge')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <Database/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Knowledge')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/observables' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/observables')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <Layers/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Observables')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/reports' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/reports')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <Assignment/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Reports')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <Divider />
            <MenuItem component={Link} to='/dashboard/explore' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/explore')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <Explore/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Explore')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/investigate' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/investigate')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <DeviceHub/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Investigate')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <Divider />
            <MenuItem component={Link} to='/dashboard/sources' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/sources')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <ClipboardArrowDown/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Sources')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <MenuItem component={Link} to='/dashboard/settings' onClick={this.handleClickAway.bind(this)} selected={location.pathname.includes('/dashboard/settings')} dense={true}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                <Settings/>
              </ListItemIcon>
              {this.state.open ? <ListItemText primary={t('Settings')} classes={{ root: classes.listText }}/> : ''}
            </MenuItem>
            <MenuItem onClick={this.toggle.bind(this)} dense={true} style={{ position: 'absolute', bottom: 10, width: '100%' }}>
              <ListItemIcon classes={{ root: classes.listIcon }}>
                {this.state.open ? <KeyboardArrowLeft/> : <KeyboardArrowRight/>}
              </ListItemIcon>
            </MenuItem>
          </MenuList>
        </Drawer>
      </ClickAwayListener>
    );
  }
}

LeftBar.propTypes = {
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withStyles(styles),
)(LeftBar);
