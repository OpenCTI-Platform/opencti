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
import {
  AssignmentOutlined,
  CasesOutlined,
  ChevronLeft,
  ChevronRight,
  ConstructionOutlined,
  DashboardOutlined,
  ExploreOutlined,
  InsertChartOutlinedOutlined,
  LayersOutlined,
} from '@mui/icons-material';
import { AssignmentOutlined, CasesOutlined, ChevronLeft, ChevronRight, ConstructionOutlined, DashboardOutlined, ExpandLess, ExpandMore, LayersOutlined } from '@mui/icons-material';
import { Binoculars, CogOutline, Database, FlaskOutline, FolderTableOutline, GlobeModel, Timetable } from 'mdi-material-ui';
import { Collapse } from '@mui/material';
import { TooltipText } from '../../../components/BreadcrumbHeader';
import useDimensions from '../../../utils/hooks/useDimensions';
import { useFormatter } from '../../../components/i18n';
import Security from '../../../utils/Security';
import useGranted, { EXPLORE, KNOWLEDGE, MODULES, SETTINGS, TAXIIAPI_SETCOLLECTIONS, VIRTUAL_ORGANIZATION_ADMIN } from '../../../utils/hooks/useGranted';
import { fileUri, MESSAGING$ } from '../../../relay/environment';
import { useIsHiddenEntities } from '../../../utils/hooks/useEntitySettings';
import useAuth from '../../../utils/hooks/useAuth';
import { useSettingsMessagesBannerHeight } from '../settings/settings_messages/SettingsMessagesBanner';
import logo_filigran from '../../../static/images/logo_filigran.png';
import useEnterpriseEdition from '../../../utils/hooks/useEnterpriseEdition';
import LeftMenuGeneric from './Menu';
import LeftMenuData from './LeftMenuData';
import LeftMenuSettings from './LeftMenuSettings';

const useStyles = makeStyles((theme) => createStyles({
  drawerPaper: {
    width: 55,
    minHeight: '100vh',
    background: 0,
    backgroundColor: theme.palette.background.nav,
    overflowX: 'hidden',
  },
  drawerPaperOpen: {
    width: 190,
    minHeight: '100vh',
    background: 0,
    backgroundColor: theme.palette.background.nav,
    overflowX: 'auto',
  },
  menuItemIcon: {
    color: theme.palette.text.primary,
  },
  menuItem: {
    height: 35,
    fontWeight: 500,
    fontSize: 14,
    paddingRight: '3px',
  },
  menuItemText: {
    padding: '1px 0 0 10px',
    fontWeight: 500,
    fontSize: 14,
  },
  menuCollapseOpen: {
    width: 190,
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
    width: 190,
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
    padding: '1px 0 0 10px',
  },
  tooltipHeader: {
    padding: '0 8px',
    fontSize: '15px',
    fontWeight: 'bold',
  },
  tooltipMenuItem: {
    margin: 0,
    padding: '4px 8px',
    minHeight: '20px',
  },
}));

export const StyledTooltip = styled(({ className, ...props }) => (
  <Tooltip {...props} arrow classes={{ popper: className }} />
))(({ theme }) => {
  return ({
    [`& .${tooltipClasses.arrow}`]: {
      color: theme.palette.mode === 'light'
        ? theme.palette.common.white
        : theme.palette.common.black,
    },
    [`& .${tooltipClasses.tooltip}`]: {
      backgroundColor: theme.palette.mode === 'light'
        ? theme.palette.common.white
        : theme.palette.common.black,
      color: theme.palette.mode === 'light'
        ? theme.palette.common.black
        : theme.palette.common.white,
      boxShadow: 'rgba(0, 0, 0, 0.2) 0px 2px 1px -1px, rgba(0, 0, 0, 0.14) 0px 1px 1px 0px, rgba(0, 0, 0, 0.12) 0px 1px 3px 0px',
    },
  });
});

const LeftBar = () => {
  const theme = useTheme();
  const location = useLocation();
  const { t_i18n } = useFormatter();

  const { settings: { platform_whitemark } } = useAuth();
  const isEnterpriseEdition = useEnterpriseEdition();

  const isGrantedToSettings = useGranted([SETTINGS]);
  const isOrganizationAdmin = useGranted([VIRTUAL_ORGANIZATION_ADMIN]);

  const [navOpen, setNavOpen] = useState(
    localStorage.getItem('navOpen') === 'true',
  );
  const [collapseSettings, setCollapseSettings] = useState(
    JSON.parse(localStorage.getItem('collapseSettings'))
    ?? {
      Analyses: false,
      Cases: false,
      Events: false,
      Observations: false,
      Threats: false,
      Arsenal: false,
      Techniques: false,
      Entities: false,
      Locations: false,
      Data: false,
      Settings: false,
    },
  );

  const classes = useStyles({ navOpen });
  const handleToggle = () => {
    localStorage.setItem('navOpen', String(!navOpen));
    setNavOpen(!navOpen);
    MESSAGING$.toggleNav.next('toggle');
  };
  const handleToggleCollapse = (entity) => {
    const updatedCollapseSettings = {
      ...collapseSettings,
      [entity]: !collapseSettings[entity],
    };
    localStorage.setItem('collapseSettings', JSON.stringify(updatedCollapseSettings));
    setCollapseSettings(updatedCollapseSettings);
  };

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
  const { dimension } = useDimensions();
  const settingsMessagesBannerHeight = useSettingsMessagesBannerHeight();
  const sidebarHeight = (!platform_whitemark || !isEnterpriseEdition)
    ? dimension.height - 150 - bannerHeightNumber
    : dimension.height - 110 - bannerHeightNumber;
  return (
    <Drawer
      variant="permanent"
      classes={{
        paper: navOpen ? classes.drawerPaperOpen : classes.drawerPaper,
      }}
      sx={{
        width: navOpen ? 190 : 55,
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.easeInOut,
          duration: theme.transitions.duration.enteringScreen,
        }),
      }}
    >
      <Toolbar />
      <div style={navOpen
        ? {
          maxHeight: sidebarHeight,
          overflowY: 'auto',
        }
        : {}
      }
      >
        <MenuList
          component="nav"
          style={{ marginTop: bannerHeightNumber + settingsMessagesBannerHeight }}
        >
          <StyledTooltip title={!navOpen && t_i18n('Home')} placement="right">
            <MenuItem
              component={Link}
              to="/dashboard"
              selected={location.pathname === '/dashboard'}
              dense={true}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                <DashboardOutlined />
              </ListItemIcon>
              {navOpen && (
                <ListItemText
                  classes={{ primary: classes.menuItemText }}
                  primary={t_i18n('Home')}
                />
              )}
            </MenuItem>
          </StyledTooltip>
        </MenuList>
        <Divider />
        <Security needs={[KNOWLEDGE]}>
          <MenuList component="nav">
            {!hideAnalyses && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Analyses' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Analyses')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <AssignmentOutlined />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Analyses')}
                      />
                      { collapseSettings.Analyses
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Analyses}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Analyses" parent="analyses" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideCases && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Cases' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Cases')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <CasesOutlined />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Cases')}
                      />
                      { collapseSettings.Cases
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Cases}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Cases" parent="cases" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideEvents && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Events' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Events')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <Timetable />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Events')}
                      />
                      { collapseSettings.Events
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Events}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Events" parent="events" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideObservations && (
              <StyledTooltip
                title={!navOpen && TooltipText({ entity_type: 'Observations' })}
                placement="right-start"
              >
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Observations')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <Binoculars />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Observations')}
                      />
                      { collapseSettings.Observations
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Observations}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Observations" parent="observations" />
                </Collapse>
              </StyledTooltip>
            )}
          </MenuList>
          <Divider />
          <MenuList component="nav">
            {!hideThreats && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Threats' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Threats')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <FlaskOutline />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Threats')}
                      />
                      { collapseSettings.Threats
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Threats}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Threats" parent="threats" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideArsenal && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Arsenal' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Arsenal')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <LayersOutlined />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Arsenal')}
                      />
                      { collapseSettings.Arsenal
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Arsenal}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Arsenal" parent="arsenal" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideTechniques && (
              <StyledTooltip
                title={!navOpen && TooltipText({ entity_type: 'Techniques' })}
                placement="right-start"
              >
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Techniques')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <ConstructionOutlined />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Techniques')}
                      />
                      { collapseSettings.Techniques
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Techniques}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Techniques" parent="techniques" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideEntities && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Entities' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Entities')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <FolderTableOutline />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Entities')}
                      />
                      { collapseSettings.Entities
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Entities}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Entities" parent="entities" />
                </Collapse>
              </StyledTooltip>
            )}
            {!hideLocations && (
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Locations' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Locations')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <GlobeModel />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Locations')}
                      />
                      { collapseSettings.Locations
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Locations}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuGeneric entity="Locations" parent="locations" />
                </Collapse>
              </StyledTooltip>
            )}
          </MenuList>
        </Security>
        <Security needs={[EXPLORE]}>
          <Divider />
          <MenuList component="nav">
            <StyledTooltip title={!navOpen && t_i18n('Dashboards')} placement="right">
            <MenuItem
              component={Link}
              to="/dashboard/workspaces/dashboards"
              selected={location.pathname.includes('/dashboard/workspaces/dashboards')}
              dense={true}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon classes={{ root: classes.menuItemIcon }} style={{ minWidth: 20 }}>
                <InsertChartOutlinedOutlined />
              </ListItemIcon>
              {navOpen && (
              <ListItemText
                classes={{ primary: classes.menuItemText }}
                primary={t_i18n('Dashboards')}
              />
              )}
            </MenuItem>
          </StyledTooltip>
          <StyledTooltip title={!navOpen && t_i18n('Investigations')} placement="right">
            <MenuItem
              component={Link}
              to="/dashboard/workspaces/investigations"
              selected={location.pathname.includes('/dashboard/workspaces/investigations')}
              dense={true}
              classes={{ root: classes.menuItem }}
            >
              <ListItemIcon classes={{ root: classes.menuItemIcon }} style={{ minWidth: 20 }}>
                <ExploreOutlined />
              </ListItemIcon>
              {navOpen && (
              <ListItemText
                classes={{ primary: classes.menuItemText }}
                primary={t_i18n('Investigations')}
              />
              )}
            </MenuItem>
          </StyledTooltip>
          <Security needs={[MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
              <StyledTooltip title={!navOpen && TooltipText({ entity_type: 'Data' })} placement="right-start">
                <MenuItem
                  onClick={navOpen
                    ? () => handleToggleCollapse('Data')
                    : () => {}
                  }
                  dense={true}
                  classes={{ root: classes.menuItem }}
                >
                  <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                    <Database />
                  </ListItemIcon>
                  {navOpen && (
                    <>
                      <ListItemText
                        classes={{ primary: classes.menuItemText }}
                        primary={t_i18n('Data')}
                      />
                      { collapseSettings.Data
                        ? <ExpandLess />
                        : <ExpandMore />
                      }
                    </>
                  )}
                </MenuItem>
                <Collapse
                  in={navOpen && collapseSettings.Data}
                  timeout="auto"
                  unmountOnExit
                >
                  <LeftMenuData />
                </Collapse>
              </StyledTooltip>
            </Security></MenuList>
      </Security>
      <Security needs={[SETTINGS, MODULES, KNOWLEDGE, TAXIIAPI_SETCOLLECTIONS]}>
        <Divider />
        <MenuList component="nav">
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
                  >
                    <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
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
                  title={!navOpen && TooltipText({ entity_type: 'Settings' })}
                  placement="right-start"
                >
                  <MenuItem
                    onClick={navOpen
                      ? () => handleToggleCollapse('Settings')
                      : () => {}
                    }
                    dense={true}
                    classes={{ root: classes.menuItem }}
                  >
                    <ListItemIcon classes={{ root: classes.menuItemIcon }}style={{ minWidth: 20 }}>
                      <CogOutline />
                    </ListItemIcon>
                    {navOpen && (
                      <>
                        <ListItemText
                          classes={{ primary: classes.menuItemText }}
                          primary={t_i18n('Settings')}
                        />
                        { collapseSettings.Settings
                          ? <ExpandLess />
                          : <ExpandMore />
                        }
                      </>
                    )}
                  </MenuItem>
                  <Collapse
                    in={navOpen && collapseSettings.Settings}
                    timeout="auto"
                    unmountOnExit
                  >
                    <LeftMenuSettings />
                  </Collapse>
                </StyledTooltip>
              )}
            </Security>
          </MenuList>
        </Security>
      </div>
      {(!platform_whitemark || !isEnterpriseEdition) && (
        <MenuItem
          dense={true}
          style={{ marginBottom: bannerHeightNumber }}
          classes={{
            root: navOpen ? classes.menuLogoOpen : classes.menuLogo,
          }}
          onClick={() => window.open('https://filigran.io/', '_blank')}
        >
          <Tooltip title={'By Filigran'} placement='right'>
            <ListItemIcon classes={{ root: classes.menuItemIcon }} style={{ minWidth: 20 }}>
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
        <ListItemIcon classes={{ root: classes.menuItemIcon }} style={{ minWidth: 20 }}>
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
