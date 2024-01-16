import React, { useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { createStyles, makeStyles, styled, useTheme } from '@mui/styles';
import Toolbar from '@mui/material/Toolbar';
import MenuList from '@mui/material/MenuList';
import MenuItem from '@mui/material/MenuItem';
import ListItemIcon from '@mui/material/ListItemIcon';
import ListItemText from '@mui/material/ListItemText';
import Divider from '@mui/material/Divider';
import Drawer from '@mui/material/Drawer';
import Tooltip, { tooltipClasses } from '@mui/material/Tooltip';
import { AssignmentOutlined, CasesOutlined, ChevronLeft, ChevronRight, ConstructionOutlined, DashboardOutlined, LayersOutlined } from '@mui/icons-material';
import { Binoculars, CogOutline, Database, FlaskOutline, FolderTableOutline, GlobeModel, Timetable } from 'mdi-material-ui';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import useGranted, { KNOWLEDGE, MODULES, SETTINGS, TAXIIAPI_SETCOLLECTIONS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';
import { fileUri, MESSAGING$ } from '../../../relay/environment';
import { useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useAuth from '../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import logo_filigran from '../../../static/images/logo_filigran.png';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';

const useStyles = makeStyles((theme) => createStyles({
  drawerPaper: {
    width: 55,
    minHeight: '100vh',
    background: 0,
    backgroundColor: theme.palette.background.nav,
    overflowX: 'hidden',
  },
  drawerPaperOpen: {
    width: 180,
    minHeight: '100vh',
    background: 0,
    backgroundColor: theme.palette.background.nav,
    overflowX: 'hidden',
  },
  menuItem: {
    height: 35,
    fontWeight: 500,
    fontSize: 14,
  },
  menuItemText: {
    padding: '1px 0 0 20px',
    fontWeight: 500,
    fontSize: 14,
  },
  menuCollapseOpen: {
    width: 180,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
    position: 'fixed',
    left: 0,
    bottom: 10,
  },
  menuCollapse: {
    width: 55,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
    position: 'fixed',
    left: 0,
    bottom: 10,
  },
  menuLogoOpen: {
    width: 180,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
    position: 'fixed',
    left: 0,
    bottom: 45,
  },
  menuLogo: {
    width: 55,
    height: 35,
    fontWeight: 500,
    fontSize: 14,
    position: 'fixed',
    left: 0,
    bottom: 45,
  },
  menuItemSmallText: {
    padding: '1px 0 0 20px',
  },
}));

const StyledTooltip = styled(({ className, ...props }) => (
  <Tooltip {...props} arrow classes={{ popper: className }} />
))(({ theme }) => ({
  [`& .${tooltipClasses.arrow}`]: {
    color: theme.palette.common.black,
  },
  [`& .${tooltipClasses.tooltip}`]: {
    backgroundColor: theme.palette.common.black,
  },
}));

const LeftBar = () => {
  const theme = useTheme();
  const location = useLocation();
  const { t_i18n } = useFormatter();

  const { settings: { platform_whitemark } } = useAuth();
  const isEnterpriseEdition = useEnterpriseEdition();

  const isGrantedToKnowledge = useGranted([KNOWLEDGE]);
  const isGrantedToModules = useGranted([MODULES]);
  const isGrantedToSettings = useGranted([SETTINGS]);
  const isOrganizationAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);

  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );

  const classes = useStyles({ navOpen });
  const handleToggle = () => {
    localStorage.setItem('navOpen', String(!navOpen));
    setNavOpen(!navOpen);
    MESSAGING$.toggleNav.next('toggle');
  };
  let toData;
  if (isGrantedToKnowledge) {
    toData = '/dashboard/data/entities';
  } else if (isGrantedToModules) {
    toData = '/dashboard/data/connectors';
  } else {
    toData = '/dashboard/data/taxii';
  }

  const hideAnalyses = useIsHiddenEntities(
    'Report',
    'Grouping',
    'Note',
    'Malware-Analysis',
  );
  const hideEvents = useIsHiddenEntities(
    'stix-sighting-relationship',
    'Incident',
    'Observed-Data',
  );
  const hideObservations = useIsHiddenEntities(
    'Stix-Cyber-Observable',
    'Artifact',
    'Indicator',
    'Infrastructure',
  );
  const hideThreats = useIsHiddenEntities(
    'Threat-Actor',
    'Intrusion-Set',
    'Campaign',
  );
  const hideEntities = useIsHiddenEntities(
    'Sector',
    'Event',
    'Organization',
    'System',
    'Individual',
  );
  const hideCases = useIsHiddenEntities(
    'Case-Incident',
    'Feedback',
    'Case-Rfi',
    'Case-Rft',
    'Task',
  );
  const hideArsenal = useIsHiddenEntities(
    'Malware',
    'Channel',
    'Tool',
    'Vulnerability',
  );
  const hideTechniques = useIsHiddenEntities(
    'Attack-Pattern',
    'Narrative',
    'Course-Of-Action',
    'Data-Component',
    'Data-Source',
  );
  const hideLocations = useIsHiddenEntities(
    'Region',
    'Administrative-Area',
    'Country',
    'City',
    'Position',
  );
  const {
    bannerSettings: { bannerHeightNumber },
  } = useAuth();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  return (
    <Drawer
      variant="permanent"
      classes={{
        paper: navOpen ? classes.drawerPaperOpen : classes.drawerPaper,
      }}
      sx={{
        width: navOpen ? 180 : 55,
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.easeInOut,
          duration: theme.transitions.duration.enteringScreen,
        }),
      }}
    >
      <Toolbar />
      <MenuList
        component="nav"
        style={{ marginTop: bannerHeightNumber + settingsMessagesBannerHeight }}
      >
        <StyledTooltip title={!navOpen && t_i18n('Dashboard')} placement="right">
          <MenuItem
            component={Link}
            to="/dashboard"
            selected={location.pathname === '/dashboard'}
            dense={true}
            classes={{ root: classes.menuItem }}
          >
            <ListItemIcon style={{ minWidth: 20 }}>
              <DashboardOutlined />
            </ListItemIcon>
            {navOpen && (
              <ListItemText
                classes={{ primary: classes.menuItemText }}
                primary={t_i18n('Dashboard')}
              />
            )}
          </MenuItem>
        </StyledTooltip>
      </MenuList>
      <Divider />
      <Security needs={[KNOWLEDGE]}>
        <MenuList component="nav">
          {!hideAnalyses && (
            <StyledTooltip title={!navOpen && t_i18n('Analyses')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/analyses"
                selected={location.pathname.includes('/dashboard/analyses')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <AssignmentOutlined />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Analyses')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideCases && (
            <StyledTooltip title={!navOpen && t_i18n('Cases')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/cases"
                selected={location.pathname.includes('/dashboard/cases')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <CasesOutlined />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Cases')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideEvents && (
            <StyledTooltip title={!navOpen && t_i18n('Events')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/events"
                selected={location.pathname.includes('/dashboard/events')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <Timetable />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Events')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideObservations && (
            <StyledTooltip
              title={!navOpen && t_i18n('Observations')}
              placement="right"
            >
              <MenuItem
                component={Link}
                to="/dashboard/observations"
                selected={location.pathname.includes('/dashboard/observations')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <Binoculars />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Observations')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
        </MenuList>
        <Divider />
        <MenuList component="nav">
          {!hideThreats && (
            <StyledTooltip title={!navOpen && t_i18n('Threats')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/threats"
                selected={location.pathname.includes('/dashboard/threats')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <FlaskOutline />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Threats')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideArsenal && (
            <StyledTooltip title={!navOpen && t_i18n('Arsenal')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/arsenal"
                selected={location.pathname.includes('/dashboard/arsenal')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <LayersOutlined />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Arsenal')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideTechniques && (
            <StyledTooltip
              title={!navOpen && t_i18n('Techniques')}
              placement="right"
            >
              <MenuItem
                component={Link}
                to="/dashboard/techniques"
                selected={location.pathname.includes('/dashboard/techniques')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <ConstructionOutlined />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Techniques')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideEntities && (
            <StyledTooltip title={!navOpen && t_i18n('Entities')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/entities"
                selected={location.pathname.includes('/dashboard/entities')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <FolderTableOutline />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Entities')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
          {!hideLocations && (
            <StyledTooltip title={!navOpen && t_i18n('Locations')} placement="right">
              <MenuItem
                component={Link}
                to="/dashboard/locations"
                selected={location.pathname.includes('/dashboard/locations')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <GlobeModel />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Locations')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          )}
        </MenuList>
      </Security>
      <Security needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
        <Divider />
        <MenuList component="nav">
          <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
            <StyledTooltip title={!navOpen && t_i18n('Data')} placement="right">
              <MenuItem
                component={Link}
                to={toData}
                selected={location.pathname.includes('/dashboard/data')}
                dense={true}
                classes={{ root: classes.menuItem }}
              >
                <ListItemIcon style={{ minWidth: 20 }}>
                  <Database />
                </ListItemIcon>
                {navOpen && (
                  <ListItemText
                    classes={{ primary: classes.menuItemText }}
                    primary={t_i18n('Data')}
                  />
                )}
              </MenuItem>
            </StyledTooltip>
          </Security>
          <Security needs={[SETTINGS, VIRTUAL_ORGANIZATION_ADMIN]}>
            {isOrganizationAdmin && !isGrantedToSettings ? (
              <StyledTooltip
                title={!navOpen && t_i18n('Settings')}
                placement="right"
              >
                <MenuItem
                  component={Link}
                  to="/dashboard/settings/accesses/organizations"
                  selected={location.pathname.includes('/dashboard/settings')}
                  dense={true}
                  classes={{ root: classes.menuItem }}
                  style={{ marginBottom: 50 }}
                >
                  <ListItemIcon style={{ minWidth: 20 }}>
                    <CogOutline />
                  </ListItemIcon>
                  {navOpen && (
                    <ListItemText
                      classes={{ primary: classes.menuItemText }}
                      primary={t_i18n('Settings')}
                    />
                  )}
                </MenuItem>
              </StyledTooltip>
            ) : (
              <StyledTooltip
                title={!navOpen && t_i18n('Settings')}
                placement="right"
              >
                <MenuItem
                  component={Link}
                  to="/dashboard/settings"
                  selected={location.pathname.includes('/dashboard/settings')}
                  dense={true}
                  classes={{ root: classes.menuItem }}
                  style={{ marginBottom: 50 }}
                >
                  <ListItemIcon style={{ minWidth: 20 }}>
                    <CogOutline />
                  </ListItemIcon>
                  {navOpen && (
                    <ListItemText
                      classes={{ primary: classes.menuItemText }}
                      primary={t_i18n('Settings')}
                    />
                  )}
                </MenuItem>
              </StyledTooltip>
            )}
          </Security>
        </MenuList>
      </Security>
      {(!platform_whitemark || !isEnterpriseEdition) && (
        <MenuItem
          dense={true}
          style={{ marginBottom: bannerHeightNumber }}
          classes={{
            root: navOpen ? classes.menuLogoOpen : classes.menuLogo,
          }}
          onClick={() => window.open('https://filigran.io/', '_blank')}
        >
          <Tooltip title={'By Filigran'}>
            <ListItemIcon style={{ minWidth: 20 }}>
              <img
                src={fileUri(logo_filigran)}
                alt="logo"
                width={20}
              />
            </ListItemIcon>
          </Tooltip>
          {navOpen && (
            <ListItemText
              classes={{ primary: classes.menuItemSmallText }}
              primary={'by Filigran'}
            />
          )}
        </MenuItem>
      )}
      <MenuItem
        dense={true}
        style={{ marginBottom: bannerHeightNumber }}
        classes={{
          root: navOpen ? classes.menuCollapseOpen : classes.menuCollapse,
        }}
        onClick={() => handleToggle()}
      >
        <ListItemIcon style={{ minWidth: 20 }}>
          {navOpen ? <ChevronLeft /> : <ChevronRight />}
        </ListItemIcon>
        {navOpen && (
          <ListItemText
            classes={{ primary: classes.menuItemText }}
            primary={t_i18n('Collapse')}
          />
        )}
      </MenuItem>
    </Drawer>
  );
};

export default LeftBar;
