import React, { useContext, useState } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { assoc, compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Toolbar from '@material-ui/core/Toolbar';
import graphql from 'babel-plugin-relay/macro';
import MenuList from '@material-ui/core/MenuList';
import MenuItem from '@material-ui/core/MenuItem';
import ListItemIcon from '@material-ui/core/ListItemIcon';
import ListItemText from '@material-ui/core/ListItemText';
import Divider from '@material-ui/core/Divider';
import Drawer from '@material-ui/core/Drawer';
import Collapse from '@material-ui/core/Collapse';
import {
  DashboardOutlined,
  ExpandLess,
  ExpandMore,
} from '@material-ui/icons';
import FiberManualRecordIcon from '@material-ui/icons/FiberManualRecord';
import PersonIcon from '@material-ui/icons/Person';
import LocationCityIcon from '@material-ui/icons/LocationCity';
import ArrowBackIcon from '@material-ui/icons/ArrowBack';
import {
  CogOutline,
  Database,
  Brain,
  GlobeModel,
} from 'mdi-material-ui';
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
    width: 255,
    backgroundColor: theme.palette.background.nav,
  },
  menuList: {
    marginTop: 20,
    marginBottom: 20,
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
    padding: '6px 10px 6px 10px',
  },
  menuItemNested: {
    height: 30,
    padding: '6px 10px 6px 25px',
  },
  bottomNavigation: {
    position: 'absolute',
    bottom: 0,
    width: '100%',
    marginBottom: 40,
  },
});

const LeftBar = ({
  t, location, history, classes,
}) => {
  const [open, setOpen] = useState({ activities: true, knowledge: true });
  const toggle = (key) => setOpen(assoc(key, !open[key], open));
  const { me } = useContext(UserContext);
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
      <MenuList component="nav"classes={{ root: classes.menuList }}>
        {/* <MenuItem
          component={Link}
          to="/dashboard"
          selected={location.pathname === '/dashboard'}
          dense={false}
          classes={{ root: classes.menuItem }}
        >
          <ListItemIcon style={{ minWidth: 35 }}>
            <DashboardOutlined />
          </ListItemIcon>
          <ListItemText primary={t('Dashboard')} />
        </MenuItem> */}
        <Security needs={[KNOWLEDGE]}>
          <MenuItem
            dense={false}
            classes={{ root: classes.menuItem }}
            onClick={() => toggle('activities')}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="#ffffff" d="M12 4.942c1.827 1.105 3.474 1.6 5 1.833v7.76c0 1.606-.415 1.935-5 4.76v-14.353zm9-1.942v11.535c0 4.603-3.203 5.804-9 9.465-5.797-3.661-9-4.862-9-9.465v-11.535c3.516 0 5.629-.134 9-3 3.371 2.866 5.484 3 9 3zm-2 1.96c-2.446-.124-4.5-.611-7-2.416-2.5 1.805-4.554 2.292-7 2.416v9.575c0 3.042 1.69 3.83 7 7.107 5.313-3.281 7-4.065 7-7.107v-9.575z"/></svg>
            </ListItemIcon>
            <ListItemText primary={t('Defender HQ')} />
          </MenuItem>
            <MenuList component="nav" disablePadding={true}>
              <MenuItem
                component={Link}
                to="/dashboard/assets"
                selected={location.pathname.includes('/dashboard/assets')}
                dense={false}
                classes={{ root: classes.menuItemNested }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FiberManualRecordIcon style={{ fontSize: '0.55rem' }}/>
                </ListItemIcon>
                <ListItemText primary={t('Assets')} />
              </MenuItem>
              <MenuItem
                component={Link}
                to="/dashboard/events"
                selected={location.pathname.includes('/dashboard/events')}
                dense={false}
                classes={{ root: classes.menuItemNested }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                </ListItemIcon>
                <ListItemText primary={t('Information Systems')} />
              </MenuItem>
            </MenuList>
          <MenuItem
            dense={false}
            classes={{ root: classes.menuItem }}
            onClick={() => toggle('knowledge')}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"><path fill="#ffffff" d="M18.905 14c-2.029 2.401-4.862 5.005-7.905 8-5.893-5.8-11-10.134-11-14.371 0-6.154 8.114-7.587 11-2.676 2.865-4.875 11-3.499 11 2.676 0 .784-.175 1.572-.497 2.371h-6.278c-.253 0-.486.137-.61.358l-.813 1.45-2.27-4.437c-.112-.219-.331-.364-.576-.38-.246-.016-.482.097-.622.299l-1.88 2.71h-1.227c-.346-.598-.992-1-1.732-1-1.103 0-2 .896-2 2s.897 2 2 2c.74 0 1.386-.402 1.732-1h1.956c.228 0 .441-.111.573-.297l.989-1.406 2.256 4.559c.114.229.343.379.598.389.256.011.496-.118.629-.337l1.759-2.908h8.013v2h-5.095z"/></svg>
            </ListItemIcon>
            <ListItemText primary={t('Activities')} />
          </MenuItem>
            <MenuList component="nav" disablePadding={true}>
              <MenuItem
                component={Link}
                to="/dashboard/threats"
                selected={location.pathname.includes('/dashboard/threats')}
                dense={false}
                classes={{ root: classes.menuItemNested }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                </ListItemIcon>
                <ListItemText primary={t('Threats Assessment')} />
              </MenuItem>
              <MenuItem
                component={Link}
                to="/dashboard/vsac"
                selected={location.pathname.includes('/dashboard/vsac')}
                dense={false}
                classes={{ root: classes.menuItemNested }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                </ListItemIcon>
                <ListItemText primary={t('Vulnerability Assessment')} />
              </MenuItem>
              <MenuItem
                component={Link}
                to="/dashboard/entities"
                selected={location.pathname.includes('/dashboard/entities')}
                dense={false}
                classes={{ root: classes.menuItemNested }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                </ListItemIcon>
                <ListItemText primary={t('Risk Assessment')} />
              </MenuItem>
            </MenuList>
        </Security>
      </MenuList>
      <Security needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
        <Divider />
        <MenuList component="nav" classes={{ root: classes.menuList }}>
            <MenuItem
              component={Link}
              to={toData}
              selected={location.pathname.includes('/dashboard/data')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <Database />
              </ListItemIcon>
              <ListItemText primary={t('Data Source')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to="/dashboard/settings"
              selected={location.pathname.includes('/dashboard/setings')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <CogOutline />
              </ListItemIcon>
              <ListItemText primary={t('Settings')} />
            </MenuItem>
            </MenuList>
            <MenuList component="nav" classes={{ root: classes.bottomNavigation }}>
            <MenuItem
              component={Link}
              to="dashboard/profile"
              selected={location.pathname.includes('dashboard/profile')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <PersonIcon />
              </ListItemIcon>
              <ListItemText primary={t(me.name)} />
            </MenuItem>
            <MenuItem
              component={Link}
              to={toData}
              selected={location.pathname.includes('/dashboard/data/dark')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <LocationCityIcon />
              </ListItemIcon>
              <ListItemText primary={t('DarkLight')} />
            </MenuItem>
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

export default compose(inject18n, withRouter, withStyles(styles))(LeftBar);
