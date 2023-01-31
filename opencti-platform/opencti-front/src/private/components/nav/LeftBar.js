import React, { useContext, useState, useEffect } from 'react';
import * as PropTypes from 'prop-types';
import { withRouter, Link } from 'react-router-dom';
import { assoc, compose } from 'ramda';
import { withStyles, withTheme } from '@material-ui/core/styles';
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
  Language,
} from '@material-ui/icons';
import FiberManualRecordIcon from '@material-ui/icons/FiberManualRecord';
import UpdateIcon from '@material-ui/icons/Update';
import PersonIcon from '@material-ui/icons/Person';
import LocationCityIcon from '@material-ui/icons/LocationCity';
import {
  CogOutline,
  Database,
} from 'mdi-material-ui';
import Dialog from '@material-ui/core/Dialog';
import { IconButton } from '@material-ui/core';
import ChevronLeftIcon from '@material-ui/icons/ChevronLeft';
import ChevronRightIcon from '@material-ui/icons/ChevronRight';
import inject18n from '../../../components/i18n';
import Security, {
  KNOWLEDGE,
  SETTINGS,
  MODULES,
  TAXIIAPI_SETCOLLECTIONS,
  UserContext,
} from '../../../utils/Security';
import {
  getAccount,
} from '../../../services/account.service';
import UserPreferencesModal from './UserPreferencesModal';
import FeatureFlag from '../../../components/feature/FeatureFlag';
import { toastGenericError } from '../../../utils/bakedToast';
import logo from '../../../resources/images/logo-mark.png';
import { QueryRenderer } from '../../../relay/environment';
import TopBar from './TopBar';

const styles = (theme) => ({
  drawerOpen: {
    width: 255,
    height: '100%',
    minHeight: '30%',
    backgroundColor: theme.palette.background.nav,
    backgroundImage: `url(${theme.waterMark})`,
    backgroundRepeat: 'no-repeat',
    backgroundPosition: '50% 70%;',
    overflowX: 'hidden',
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    '@media (min-height: 200px)': {
      overflowY: 'auto',
      overflowX: 'hidden',
    },
    '@media (min-height: 250px)': {
      overflow: 'hidden',
    },
  },
  gridOpen: {
    display: 'grid',
    gridTemplateColumns: '255px 1fr',
    transition: theme.transitions.create('grid-template-columns', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
    overflow: 'hidden',
  },
  drawerClose: {
    backgroundColor: theme.palette.background.nav,
    overflow: 'hidden',
    height: '100%',
    minHeight: '30%',
    width: theme.spacing(7) + 1,
    [theme.breakpoints.up('sm')]: {
      width: theme.spacing(9) + 1,
    },
    transition: theme.transitions.create('width', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  gridClose: {
    display: 'grid',
    gridTemplateColumns: '75px 1fr',
    transition: theme.transitions.create('grid-template-columns', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
    overflow: 'hidden',
  },
  menuList: {
    marginTop: 20,
    marginBottom: 20,
  },
  menuItem: {
    height: 40,
    padding: '6px 10px 6px 10px',
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  menuItemClose: {
    height: 40,
    padding: '6px 10px 6px 20px',
    transition: theme.transitions.create('padding', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  menuItemNested: {
    height: 30,
    padding: '6px 10px 6px 25px',
  },
  toolbar: theme.mixins.toolbar,
  container: {
    position: 'relative',
    minHeight: '100%',
  },
  topNavigation: {
    minHeight: '70%',
    position: 'relative',
    top: '0',
  },
  bottomNavigation: {
    position: 'relative',
    left: 0,
    bottom: 16,
    width: '100%',
    minHeight: '30%',
    display: 'flex',
    alignItems: 'flex-end',
  },
  logoContainer: {
    height: 64,
    width: 255,
    paddingTop: 15,
    paddingBottom: 15,
    borderBottom: '1px solid rgba(255, 255, 255, 0.2)',
  },
  logo: {
    cursor: 'pointer',
    height: 20,
    marginTop: 10,
    marginLeft: 10,
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.enteringScreen,
    }),
  },
  logoClose: {
    cursor: 'pointer',
    height: 20,
    marginTop: 10,
    marginLeft: 20,
    transition: theme.transitions.create('margin', {
      easing: theme.transitions.easing.sharp,
      duration: theme.transitions.duration.leavingScreen,
    }),
  },
  hideText: {
    display: 'none',
  },
  drawerButton: {
    position: 'absolute',
    left: '90%',
    top: '48%',
    zIndex: 2,
  },
  drawerButtonCollapsed: {
    position: 'absolute',
    left: '64%',
    top: '48%',
    zIndex: 2,
  },
  drawerButtonMargin: {
    margin: '0 20px 0 0',
    borderRadius: '25% 0 0 25%',
    padding: '12px 1px',
    backgroundColor: 'rgba(255, 255, 255, 0.08)',
    '&:hover': {
      backgroundColor: 'rgba(255, 255, 255, 0.2)',
    },
  },
});

const leftBarVersionQuery = graphql`
  query LeftBarVersionQuery {
    about {
      version
    }
  }
`;

const LeftBar = ({
  t, location, classes, clientId, history, setClientId, theme, children,
}) => {
  const [open, setOpen] = useState({ activities: true, knowledge: true });
  const [user, setUser] = useState();
  const [currentOrg, setCurrentOrg] = useState();
  const [userPrefOpen, setUserPrefOpen] = useState(false);
  const [openDrawer, setOpenDrawer] = useState(true);
  const toggle = (key) => setOpen(assoc(key, !open[key], open));
  const { me } = useContext(UserContext);

  useEffect(() => {
    if (clientId) {
      getAccount()
        .then((res) => {
          setUser({
            email: res.data.email,
            clients: res.data.clients,
            first_name: me.name,
            last_name: me.lastname,
          });
          localStorage.setItem('currentOrg', res.data.clients.find((obj) => obj.client_id === clientId).name);
          setCurrentOrg(res.data.clients.find((obj) => obj.client_id === clientId).name);
        }).catch(() => {
          toastGenericError('Failed to get user information');
        });
    }
  }, [clientId]);

  const handleUserPrefOpen = () => {
    setUserPrefOpen(true);
  };

  const handleDialogClose = () => {
    setUserPrefOpen(null);
  };

  const cancelUserPref = () => {
    setUserPrefOpen(null);
  };

  const handleDrawerClose = () => {
    setOpenDrawer(!openDrawer);
  };

  return (
    <div className={openDrawer ? classes.gridOpen : classes.gridClose}>
      <TopBar drawer={!openDrawer} />
      <Drawer
        variant="permanent"
        className={openDrawer ? classes.drawerOpen : classes.drawerClose}
        classes={{
          paper: openDrawer ? classes.drawerOpen : classes.drawerClose,
        }}
      >
      <div className={classes.container}>
        <div className={classes.topNavigation}>
          <div
            className={
              openDrawer ? classes.drawerButton : classes.drawerButtonCollapsed
            }
          >
            <IconButton
              onClick={handleDrawerClose}
              className={!openDrawer && classes.drawerButtonMargin}
              classes={{ root: classes.drawerButtonMargin }}
            >
              {openDrawer ? <ChevronLeftIcon /> : <ChevronRightIcon />}
            </IconButton>
          </div>
          <div className={classes.logoContainer}>
            <Link to="/dashboard">
              <img
                src={openDrawer ? theme.logo : logo}
                alt="logo"
                className={openDrawer ? classes.logo : classes.logoClose}
              />
            </Link>
          </div>
          {/* <Toolbar /> */}
          <MenuList component="nav" classes={{ root: classes.menuList }}>
            <MenuItem
              component={Link}
              to="/dashboard"
              selected={location.pathname === '/dashboard'}
              dense={false}
              classes={{
                root: openDrawer ? classes.menuItem : classes.menuItemClose,
              }}
            >
              <ListItemIcon style={{ minWidth: 35 }}>
                <DashboardOutlined />
              </ListItemIcon>
              <ListItemText
                primary={t('Dashboard')}
                className={!openDrawer && classes.hideText}
              />
            </MenuItem>
            <Security needs={[KNOWLEDGE]}>
              <MenuItem
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
                onClick={() => toggle('activities')}
                component={Link}
                to="/defender HQ/assets"
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                  >
                    <path
                      fill="#ffffff"
                      d="M12 4.942c1.827 1.105 3.474 1.6 5 1.833v7.76c0 1.606-.415 1.935-5 4.76v-14.353zm9-1.942v11.535c0 4.603-3.203 5.804-9 9.465-5.797-3.661-9-4.862-9-9.465v-11.535c3.516 0 5.629-.134 9-3 3.371 2.866 5.484 3 9 3zm-2 1.96c-2.446-.124-4.5-.611-7-2.416-2.5 1.805-4.554 2.292-7 2.416v9.575c0 3.042 1.69 3.83 7 7.107 5.313-3.281 7-4.065 7-7.107v-9.575z"
                    />
                  </svg>
                </ListItemIcon>
                <ListItemText
                  primary={t('Defender HQ')}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
              <Collapse in={openDrawer}>
                <MenuList component="nav" disablePadding={true}>
                  <MenuItem
                    component={Link}
                    to="/defender HQ/assets"
                    selected={location.pathname.includes('/defender HQ/assets')}
                    dense={false}
                    classes={{ root: classes.menuItemNested }}
                  >
                    <ListItemIcon style={{ minWidth: 35 }}>
                      <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                    </ListItemIcon>
                    <ListItemText primary={t('Assets')} data-cy="assets" />
                  </MenuItem>
                  <MenuItem
                    disabled={true}
                    component={Link}
                    to="/dashboard/events"
                    selected={location.pathname.includes('/dashboard/events')}
                    dense={false}
                    classes={{ root: classes.menuItemNested }}
                  >
                    <ListItemIcon style={{ minWidth: 35 }}>
                      <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={t('Information Systems')}
                      data-cy="information systems"
                    />
                  </MenuItem>
                </MenuList>
              </Collapse>
              <MenuItem
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
                onClick={() => toggle('knowledge')}
                component={Link}
                to="/activities/risk_assessment"
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <svg
                    xmlns="http://www.w3.org/2000/svg"
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                  >
                    <path
                      fill="#ffffff"
                      d="M18.905 14c-2.029 2.401-4.862 5.005-7.905 8-5.893-5.8-11-10.134-11-14.371 0-6.154 8.114-7.587 11-2.676 2.865-4.875 11-3.499 11 2.676 0 .784-.175 1.572-.497 2.371h-6.278c-.253 0-.486.137-.61.358l-.813 1.45-2.27-4.437c-.112-.219-.331-.364-.576-.38-.246-.016-.482.097-.622.299l-1.88 2.71h-1.227c-.346-.598-.992-1-1.732-1-1.103 0-2 .896-2 2s.897 2 2 2c.74 0 1.386-.402 1.732-1h1.956c.228 0 .441-.111.573-.297l.989-1.406 2.256 4.559c.114.229.343.379.598.389.256.011.496-.118.629-.337l1.759-2.908h8.013v2h-5.095z"
                    />
                  </svg>
                </ListItemIcon>
                <ListItemText
                  primary={t('Activities')}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
              <Collapse in={openDrawer}>
                <MenuList component="nav" disablePadding={true}>
                  <MenuItem
                    disabled={true}
                    component={Link}
                    to="/dashboard/threats"
                    selected={location.pathname.includes('/dashboard/threats')}
                    dense={false}
                    classes={{ root: classes.menuItemNested }}
                  >
                    <ListItemIcon style={{ minWidth: 35 }}>
                      <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={t('Threats Assessment')}
                      data-cy="threats assessment"
                    />
                  </MenuItem>
                  <MenuItem
                    component={Link}
                    to="/activities/vulnerability_assessment"
                    selected={location.pathname.includes(
                      '/activities/vulnerability_assessment',
                    )}
                    dense={false}
                    classes={{ root: classes.menuItemNested }}
                  >
                    <ListItemIcon style={{ minWidth: 35 }}>
                      <FiberManualRecordIcon style={{ fontSize: '0.55rem' }} />
                    </ListItemIcon>
                    <ListItemText
                      primary={t('Vulnerability Assessment')}
                      data-cy="vsac"
                    />
                  </MenuItem>
                  <FeatureFlag tag={'RISK_ASSESSMENT'}>
                    <MenuItem
                      component={Link}
                      to="/activities/risk_assessment"
                      selected={location.pathname.includes(
                        '/activities/risk_assessment',
                      )}
                      dense={false}
                      classes={{ root: classes.menuItemNested }}
                    >
                      <ListItemIcon style={{ minWidth: 35 }}>
                        <FiberManualRecordIcon
                          style={{ fontSize: '0.55rem' }}
                        />
                      </ListItemIcon>
                      <ListItemText
                        primary={t('Risk Assessment')}
                        data-cy="risk assessment"
                      />
                    </MenuItem>
                  </FeatureFlag>
                </MenuList>
              </Collapse>
            </Security>
          </MenuList>
          <Security
            needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}
          >
            <Divider />
            <MenuList component="nav" classes={{ root: classes.menuList }}>
              <MenuItem
                component={Link}
                to={'/data'}
                selected={location.pathname.includes('/data')}
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <Database />
                </ListItemIcon>
                <ListItemText
                  primary={t('Data')}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
              <MenuItem
                disabled={true}
                component={Link}
                to="/dashboard/settings"
                selected={location.pathname.includes('/dashboard/setings')}
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <CogOutline />
                </ListItemIcon>
                <ListItemText
                  primary={t('Settings')}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
              <MenuItem
                disabled={true}
                component={Link}
                to={'/about'}
                selected={location.pathname.includes('/about')}
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <Language />
                </ListItemIcon>
                <ListItemText
                  primary={t('About')}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
            </MenuList>
          </Security>
        </div>
        <Security
          needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}
        >
          <div className={classes.bottomNavigation}>
            <MenuList component="nav" classes={{ root: classes.menuList }}>
              <QueryRenderer
                query={leftBarVersionQuery}
                render={({ props: about }) => {
                  if (about) {
                    const { version } = about.about;
                    if (version.includes('-')) {
                      return (
                        <MenuItem
                          disabled={true}
                          dense={false}
                          classes={{
                            root: openDrawer
                              ? classes.menuItem
                              : classes.menuItemClose,
                          }}
                        >
                          <ListItemIcon style={{ minWidth: 35 }}>
                            <UpdateIcon />
                          </ListItemIcon>
                          <ListItemText
                            primary={version}
                            className={!openDrawer && classes.hideText}
                          />
                        </MenuItem>
                      );
                    }
                  }
                  return '';
                }}
              />
              <MenuItem
                // component={Link}
                // to="/dashboard/profile"
                selected={location.pathname.includes('/dashboard/profile')}
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <PersonIcon />
                </ListItemIcon>
                <ListItemText
                  primary={t(me.name)}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
              <MenuItem
                onClick={() => handleUserPrefOpen()}
                dense={false}
                classes={{
                  root: openDrawer ? classes.menuItem : classes.menuItemClose,
                }}
              >
                <ListItemIcon style={{ minWidth: 35 }}>
                  <LocationCityIcon />
                </ListItemIcon>
                <ListItemText
                  primary={currentOrg}
                  className={!openDrawer && classes.hideText}
                />
              </MenuItem>
            </MenuList>
          </div>
        </Security>
        </div>
        <Dialog
          open={userPrefOpen}
          onClose={() => handleDialogClose()}
          maxWidth="md"
        >
          <UserPreferencesModal
            me={me}
            user={user}
            isLoading="true"
            history={history}
            action={cancelUserPref}
            url={location.pathname}
            setClientId={setClientId}
          />
        </Dialog>
      </Drawer>
      <div style={{ padding: '0 1rem' }}>{children}</div>
    </div>
  );
};

LeftBar.propTypes = {
  children: PropTypes.node,
  drawerValue: PropTypes.func,
  location: PropTypes.object,
  classes: PropTypes.object,
  t: PropTypes.func,
  clientId: PropTypes.string,
  theme: PropTypes.object,
};

export default compose(inject18n, withRouter, withTheme, withStyles(styles))(LeftBar);
