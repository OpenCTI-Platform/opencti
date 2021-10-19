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
  AssignmentOutlined,
  LayersOutlined,
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
  Binoculars,
  FlaskOutline,
  FolderTableOutline,
  Timetable,
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
import { commitMutation } from '../../../relay/environment';

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

const logoutMutation = graphql`
  mutation TopBarLogoutMutation {
    logout
  }
`;

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

  const handleLogout = () => {
    commitMutation({
      mutation: logoutMutation,
      variables: {},
      onCompleted: () => history.push('/'),
    });
  };

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
              <Brain />
            </ListItemIcon>
            <ListItemText primary={t('Defender HQ')} />
          </MenuItem>
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
          <MenuItem
            dense={false}
            classes={{ root: classes.menuItem }}
            onClick={() => toggle('knowledge')}
          >
            <ListItemIcon style={{ minWidth: 35 }}>
              <GlobeModel />
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
              <ListItemText primary={t('Dark Light')} />
            </MenuItem>
            <MenuItem
              component={Link}
              onClick={handleLogout}
              dense={false}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <ArrowBackIcon />
              </ListItemIcon>
              <ListItemText primary={t('Sign Out')} />
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
