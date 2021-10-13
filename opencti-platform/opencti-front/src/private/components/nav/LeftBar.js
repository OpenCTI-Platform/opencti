import React, { useContext, useState } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { assoc, compose } from 'ramda';
import { withStyles } from '@material-ui/core/styles';
import Toolbar from '@material-ui/core/Toolbar';
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

const LeftBar = ({ t, location, classes }) => {
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
      <MenuList component="nav">
        <MenuItem
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
        </MenuItem>
        <Security needs={[KNOWLEDGE]}>
          <MenuItem
            dense={false}
            classes={{ root: classes.menuItem }}
            onClick={() => toggle('activities')}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <Brain />
            </ListItemIcon>
            <ListItemText primary={t('Defender HQ')} />
            {open.activities ? <ExpandLess /> : <ExpandMore />}
          </MenuItem>
          <Collapse in={open.activities}>
            <MenuList component="nav" disablePadding={true}>
              <MenuItem
                component={Link}
                to="/dashboard/analysis"
                selected={location.pathname.includes('/dashboard/analysis')}
                dense={false}
                classes={{ root: classes.menuItemNested }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <FiberManualRecordIcon style={{ fontSize: '0.55rem' }}/>
                </ListItemIcon>
                <ListItemText primary={t('Assests')} />
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
          </Collapse>
          <MenuItem
            dense={false}
            classes={{ root: classes.menuItem }}
            onClick={() => toggle('knowledge')}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <GlobeModel />
            </ListItemIcon>
            <ListItemText primary={t('Activities')} />
            {open.knowledge ? <ExpandLess /> : <ExpandMore />}
          </MenuItem>
          <Collapse in={open.knowledge}>
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
          </Collapse>
        </Security>
      </MenuList>
      <Security needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
        <Divider />
        <MenuList component="nav" classes={{ root: classes.bottomNavigation }}>
          <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
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
              to={toData}
              selected={location.pathname.includes('/dashboard/duane')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <PersonIcon />
              </ListItemIcon>
              <ListItemText primary={t('Duane Davis')} />
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
              <ListItemText primary={t('Dark Light')} />
            </MenuItem>
            <MenuItem
              component={Link}
              to={toData}
              selected={location.pathname.includes('/dashboard/data/sign')}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <ArrowBackIcon />
              </ListItemIcon>
              <ListItemText primary={t('Sign Out')} />
            </MenuItem>
          </Security>
          <Security needs={[SETTINGS]}>
            <MenuItem
              component={Link}
              to="/dashboard/settings"
              selected={location.pathname.includes('/dashboard/settings')}
              dense={false}
              classes={{ root: classes.menuItem }}
              style={{ marginBottom: 50 }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <CogOutline />
              </ListItemIcon>
              <ListItemText primary={t('Settings')} />
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

export default compose(inject18n, withRouter, withStyles(styles))(LeftBar);
