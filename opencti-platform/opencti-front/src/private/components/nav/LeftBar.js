import React, { useContext, useState } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { assoc, compose } from 'ramda';
import { withStyles, withTheme } from '@mui/styles';
import Toolbar from '@mui/material/Toolbar';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Divider from '@mui/material/Divider';
import Drawer from '@mui/material/Drawer';
import Collapse from '@mui/material/Collapse';
import {
  DashboardOutlined,
  ExpandLess,
  ExpandMore,
} from '@mui/icons-material';
import {
  CogOutline,
  Database,
  FolderTableOutline,
  GlobeModel,
} from 'mdi-material-ui';
import * as R from 'ramda';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE,
  SETTINGS,
  MODULES,
  TAXIIAPI_SETCOLLECTIONS,
  UserContext,
  granted,
} from '../../../utils/Security';

const styles = (theme) => ({
  drawerPaper: {
    minHeight: '100vh',
    width: 180,
    background: 0,
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
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuItemNested: {
    height: 30,
    paddingLeft: 35,
  },
  menuItemText: {
    paddingTop: 1,
    fontWeight: 500,
    fontSize: 14,
  },
  menuItemNestedText: {
    paddingTop: 1,
    fontWeight: 500,
    fontSize: 14,
    color: theme.palette.text.secondary,
  },
});

const LeftBar = ({ t, location, classes, theme }) => {
  const [open, setOpen] = useState({ activities: true, knowledge: true, disinformation: true });
  const toggle = (key) => setOpen(assoc(key, !open[key], open));
  const { me, settings } = useContext(UserContext);
  const menusPerCategory = R.groupBy((menu) => menu.category, settings.platform_menu);
  let toData;
  if (granted(me, [KNOWLEDGE])) {
    toData = '/dashboard/data/entities';
  } else if (granted(me, [MODULES])) {
    toData = '/dashboard/data/connectors';
  } else {
    toData = '/dashboard/data/taxii';
  }
  return (
    <Drawer variant="permanent" classes={{ paper: classes.drawerPaper }}>
      <Toolbar />
      <MenuList component="nav">
        <MenuItem component={Link} to="/dashboard" selected={location.pathname === '/dashboard'}
          dense={true} classes={{ root: classes.menuItem }}>
          <ListItemIcon style={{ minWidth: 30 }}>
            <DashboardOutlined fontSize="small" color="primary" />
          </ListItemIcon>
          <ListItemText classes={{ primary: classes.menuItemText }} primary={t('Dashboard')}/>
        </MenuItem>
        <Security needs={[KNOWLEDGE]}>
          { Object.entries(menusPerCategory).map(([category, menus]) => <div key={`list_${category}`}>
               {/* eslint-disable-next-line max-len */}
              <MenuItem key={`menu_${category}`} dense={true} classes={{ root: classes.menuItem }} onClick={() => toggle(category)}>
                <ListItemIcon style={{ minWidth: 30 }}>
                  <GlobeModel fontSize="small" color="primary" />
                </ListItemIcon>
                {/* eslint-disable-next-line max-len */}
                <ListItemText classes={{ primary: classes.menuItemText }} primary={t(category)}/>
                {open.disinformation ? <ExpandLess /> : <ExpandMore />}
              </MenuItem>
              <Collapse key={`collapse_${category}`} in={open.disinformation}>
                <MenuList component="nav" disablePadding={true}>
                { menus.map((menu) => <MenuItem key={menu.id} component={Link} to={`/dashboard/${menu.id}`}
                                   selected={location.pathname.includes(`/dashboard/${menu.id}`)} dense={true}
                                   classes={{ root: classes.menuItemNested }}>
                    {/* eslint-disable-next-line max-len */}
                    <ListItemIcon style={{ minWidth: 30, color: theme.palette.text.secondary }}>
                      <FolderTableOutline fontSize="small" color="inherit" />
                    </ListItemIcon>
                    {/* eslint-disable-next-line max-len */}
                    <ListItemText classes={{ primary: classes.menuItemNestedText }} primary={t(menu.name)}/>
                  </MenuItem>)}
                </MenuList>
              </Collapse>
            </div>)}
        </Security>
      </MenuList>
      <Security needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
        <Divider />
        <MenuList component="nav" disablePadding={true}>
          <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
            <MenuItem
              component={Link}
              to={toData}
              selected={location.pathname.includes('/dashboard/data')}
              dense={true}
              classes={{ root: classes.menuItem }}>
              <ListItemIcon style={{ minWidth: 30 }}>
                <Database fontSize="small" color="primary" />
              </ListItemIcon>
              <ListItemText
                classes={{ primary: classes.menuItemText }}
                primary={t('Data')}
              />
            </MenuItem>
          </Security>
          <Security needs={[SETTINGS]}>
            <MenuItem
              component={Link}
              to="/dashboard/settings"
              selected={location.pathname.includes('/dashboard/settings')}
              dense={true}
              classes={{ root: classes.menuItem }}
              style={{ marginBottom: 50 }}
            >
              <ListItemIcon style={{ minWidth: 30 }}>
                <CogOutline fontSize="small" color="primary" />
              </ListItemIcon>
              <ListItemText
                classes={{ primary: classes.menuItemText }}
                primary={t('Settings')}
              />
            </MenuItem>
          </Security>
        </MenuList>
      </Security>
    </Drawer>
  );
};

LeftBar.propTypes = {
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
};

export default compose(
  inject18n,
  withRouter,
  withTheme,
  withStyles(styles),
)(LeftBar);
